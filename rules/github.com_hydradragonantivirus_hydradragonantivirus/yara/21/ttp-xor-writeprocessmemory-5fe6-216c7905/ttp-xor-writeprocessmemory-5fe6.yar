rule TTP_XOR_WriteProcessMemory_5fe6 {
  strings:
    $key_5fe6 = { 08 94 [2] 3a b6 [2] 3c 83 [2] 12 83 [2] 2d 9f }

  condition:
    any of them
}