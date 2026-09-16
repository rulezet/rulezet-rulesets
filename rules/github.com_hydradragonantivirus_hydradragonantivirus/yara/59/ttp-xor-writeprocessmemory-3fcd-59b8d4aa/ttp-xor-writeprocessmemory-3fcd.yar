rule TTP_XOR_WriteProcessMemory_3fcd {
  strings:
    $key_3fcd = { 68 bf [2] 5a 9d [2] 5c a8 [2] 72 a8 [2] 4d b4 }

  condition:
    any of them
}