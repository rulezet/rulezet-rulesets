rule TTP_XOR_WriteProcessMemory_5f53 {
  strings:
    $key_5f53 = { 08 21 [2] 3a 03 [2] 3c 36 [2] 12 36 [2] 2d 2a }

  condition:
    any of them
}