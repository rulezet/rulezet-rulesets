rule TTP_XOR_WriteProcessMemory_66da {
  strings:
    $key_66da = { 31 a8 [2] 03 8a [2] 05 bf [2] 2b bf [2] 14 a3 }

  condition:
    any of them
}