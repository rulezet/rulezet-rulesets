rule TTP_XOR_WriteProcessMemory_6dda {
  strings:
    $key_6dda = { 3a a8 [2] 08 8a [2] 0e bf [2] 20 bf [2] 1f a3 }

  condition:
    any of them
}