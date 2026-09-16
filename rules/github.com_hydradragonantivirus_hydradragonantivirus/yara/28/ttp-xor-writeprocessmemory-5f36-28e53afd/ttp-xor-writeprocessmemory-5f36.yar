rule TTP_XOR_WriteProcessMemory_5f36 {
  strings:
    $key_5f36 = { 08 44 [2] 3a 66 [2] 3c 53 [2] 12 53 [2] 2d 4f }

  condition:
    any of them
}