rule TTP_XOR_WriteProcessMemory_5f02 {
  strings:
    $key_5f02 = { 08 70 [2] 3a 52 [2] 3c 67 [2] 12 67 [2] 2d 7b }

  condition:
    any of them
}