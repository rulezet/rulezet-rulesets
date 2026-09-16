rule TTP_XOR_WriteProcessMemory_36da {
  strings:
    $key_36da = { 61 a8 [2] 53 8a [2] 55 bf [2] 7b bf [2] 44 a3 }

  condition:
    any of them
}