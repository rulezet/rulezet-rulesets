rule TTP_XOR_WriteProcessMemory_5f43 {
  strings:
    $key_5f43 = { 08 31 [2] 3a 13 [2] 3c 26 [2] 12 26 [2] 2d 3a }

  condition:
    any of them
}