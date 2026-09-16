rule TTP_XOR_WriteProcessMemory_4dda {
  strings:
    $key_4dda = { 1a a8 [2] 28 8a [2] 2e bf [2] 00 bf [2] 3f a3 }

  condition:
    any of them
}