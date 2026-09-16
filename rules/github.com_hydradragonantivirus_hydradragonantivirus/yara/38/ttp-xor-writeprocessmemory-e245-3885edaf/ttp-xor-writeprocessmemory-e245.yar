rule TTP_XOR_WriteProcessMemory_e245 {
  strings:
    $key_e245 = { b5 37 [2] 87 15 [2] 81 20 [2] af 20 [2] 90 3c }

  condition:
    any of them
}