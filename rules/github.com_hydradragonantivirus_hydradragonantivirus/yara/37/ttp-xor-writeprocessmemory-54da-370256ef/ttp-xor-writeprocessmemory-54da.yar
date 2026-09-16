rule TTP_XOR_WriteProcessMemory_54da {
  strings:
    $key_54da = { 03 a8 [2] 31 8a [2] 37 bf [2] 19 bf [2] 26 a3 }

  condition:
    any of them
}