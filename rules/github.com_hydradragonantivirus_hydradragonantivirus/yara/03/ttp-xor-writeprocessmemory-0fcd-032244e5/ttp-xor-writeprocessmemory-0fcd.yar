rule TTP_XOR_WriteProcessMemory_0fcd {
  strings:
    $key_0fcd = { 58 bf [2] 6a 9d [2] 6c a8 [2] 42 a8 [2] 7d b4 }

  condition:
    any of them
}