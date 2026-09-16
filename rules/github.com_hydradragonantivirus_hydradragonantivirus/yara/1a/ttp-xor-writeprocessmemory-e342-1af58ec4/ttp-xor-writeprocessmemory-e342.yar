rule TTP_XOR_WriteProcessMemory_e342 {
  strings:
    $key_e342 = { b4 30 [2] 86 12 [2] 80 27 [2] ae 27 [2] 91 3b }

  condition:
    any of them
}