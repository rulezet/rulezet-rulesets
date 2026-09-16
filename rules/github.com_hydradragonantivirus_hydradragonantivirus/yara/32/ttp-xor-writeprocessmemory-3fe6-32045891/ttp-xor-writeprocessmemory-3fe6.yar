rule TTP_XOR_WriteProcessMemory_3fe6 {
  strings:
    $key_3fe6 = { 68 94 [2] 5a b6 [2] 5c 83 [2] 72 83 [2] 4d 9f }

  condition:
    any of them
}