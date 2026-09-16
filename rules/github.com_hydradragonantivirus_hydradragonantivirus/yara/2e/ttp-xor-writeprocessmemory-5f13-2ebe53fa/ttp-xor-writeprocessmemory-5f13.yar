rule TTP_XOR_WriteProcessMemory_5f13 {
  strings:
    $key_5f13 = { 08 61 [2] 3a 43 [2] 3c 76 [2] 12 76 [2] 2d 6a }

  condition:
    any of them
}