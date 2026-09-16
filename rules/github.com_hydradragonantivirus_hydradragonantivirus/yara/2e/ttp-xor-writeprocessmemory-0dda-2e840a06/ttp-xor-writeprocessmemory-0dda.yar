rule TTP_XOR_WriteProcessMemory_0dda {
  strings:
    $key_0dda = { 5a a8 [2] 68 8a [2] 6e bf [2] 40 bf [2] 7f a3 }

  condition:
    any of them
}