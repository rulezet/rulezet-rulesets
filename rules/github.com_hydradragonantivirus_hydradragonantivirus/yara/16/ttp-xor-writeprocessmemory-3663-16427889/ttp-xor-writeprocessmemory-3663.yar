rule TTP_XOR_WriteProcessMemory_3663 {
  strings:
    $key_3663 = { 61 11 [2] 53 33 [2] 55 06 [2] 7b 06 [2] 44 1a }

  condition:
    any of them
}