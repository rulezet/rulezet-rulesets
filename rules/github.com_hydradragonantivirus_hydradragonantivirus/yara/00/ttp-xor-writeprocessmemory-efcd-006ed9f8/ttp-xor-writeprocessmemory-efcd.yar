rule TTP_XOR_WriteProcessMemory_efcd {
  strings:
    $key_efcd = { b8 bf [2] 8a 9d [2] 8c a8 [2] a2 a8 [2] 9d b4 }

  condition:
    any of them
}