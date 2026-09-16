rule TTP_XOR_WriteProcessMemory_47da {
  strings:
    $key_47da = { 10 a8 [2] 22 8a [2] 24 bf [2] 0a bf [2] 35 a3 }

  condition:
    any of them
}