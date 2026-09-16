rule TTP_XOR_WriteProcessMemory_35da {
  strings:
    $key_35da = { 62 a8 [2] 50 8a [2] 56 bf [2] 78 bf [2] 47 a3 }

  condition:
    any of them
}