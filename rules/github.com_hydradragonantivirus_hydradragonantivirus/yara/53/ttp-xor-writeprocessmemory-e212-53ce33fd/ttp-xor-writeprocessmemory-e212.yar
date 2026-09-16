rule TTP_XOR_WriteProcessMemory_e212 {
  strings:
    $key_e212 = { b5 60 [2] 87 42 [2] 81 77 [2] af 77 [2] 90 6b }

  condition:
    any of them
}