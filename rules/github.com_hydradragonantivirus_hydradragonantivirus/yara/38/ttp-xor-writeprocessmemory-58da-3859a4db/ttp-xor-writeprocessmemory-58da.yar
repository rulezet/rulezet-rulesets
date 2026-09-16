rule TTP_XOR_WriteProcessMemory_58da {
  strings:
    $key_58da = { 0f a8 [2] 3d 8a [2] 3b bf [2] 15 bf [2] 2a a3 }

  condition:
    any of them
}