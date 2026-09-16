rule TTP_XOR_WriteProcessMemory_2dda {
  strings:
    $key_2dda = { 7a a8 [2] 48 8a [2] 4e bf [2] 60 bf [2] 5f a3 }

  condition:
    any of them
}