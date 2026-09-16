rule TTP_XOR_WriteProcessMemory_55da {
  strings:
    $key_55da = { 02 a8 [2] 30 8a [2] 36 bf [2] 18 bf [2] 27 a3 }

  condition:
    any of them
}