rule TTP_XOR_WriteProcessMemory_56da {
  strings:
    $key_56da = { 01 a8 [2] 33 8a [2] 35 bf [2] 1b bf [2] 24 a3 }

  condition:
    any of them
}