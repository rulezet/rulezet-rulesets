rule TTP_XOR_WriteProcessMemory_18a2 {
  strings:
    $key_18a2 = { 4f d0 [2] 7d f2 [2] 7b c7 [2] 55 c7 [2] 6a db }

  condition:
    any of them
}