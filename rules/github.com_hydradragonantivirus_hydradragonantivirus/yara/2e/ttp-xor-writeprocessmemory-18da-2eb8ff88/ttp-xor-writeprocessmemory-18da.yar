rule TTP_XOR_WriteProcessMemory_18da {
  strings:
    $key_18da = { 4f a8 [2] 7d 8a [2] 7b bf [2] 55 bf [2] 6a a3 }

  condition:
    any of them
}