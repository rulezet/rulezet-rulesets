rule TTP_XOR_WriteProcessMemory_7fcd {
  strings:
    $key_7fcd = { 28 bf [2] 1a 9d [2] 1c a8 [2] 32 a8 [2] 0d b4 }

  condition:
    any of them
}