rule TTP_XOR_WriteProcessMemory_e205 {
  strings:
    $key_e205 = { b5 77 [2] 87 55 [2] 81 60 [2] af 60 [2] 90 7c }

  condition:
    any of them
}