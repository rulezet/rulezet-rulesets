rule TTP_XOR_WriteProcessMemory_7dda {
  strings:
    $key_7dda = { 2a a8 [2] 18 8a [2] 1e bf [2] 30 bf [2] 0f a3 }

  condition:
    any of them
}