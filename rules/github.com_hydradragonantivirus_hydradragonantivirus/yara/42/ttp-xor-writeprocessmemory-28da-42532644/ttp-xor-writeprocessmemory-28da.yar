rule TTP_XOR_WriteProcessMemory_28da {
  strings:
    $key_28da = { 7f a8 [2] 4d 8a [2] 4b bf [2] 65 bf [2] 5a a3 }

  condition:
    any of them
}