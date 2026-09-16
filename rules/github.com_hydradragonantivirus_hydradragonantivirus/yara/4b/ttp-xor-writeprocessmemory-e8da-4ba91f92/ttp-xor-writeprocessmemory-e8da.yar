rule TTP_XOR_WriteProcessMemory_e8da {
  strings:
    $key_e8da = { bf a8 [2] 8d 8a [2] 8b bf [2] a5 bf [2] 9a a3 }

  condition:
    any of them
}