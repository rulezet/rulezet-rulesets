rule TTP_XOR_WriteProcessMemory_0ee6 {
  strings:
    $key_0ee6 = { 59 94 [2] 6b b6 [2] 6d 83 [2] 43 83 [2] 7c 9f }

  condition:
    any of them
}