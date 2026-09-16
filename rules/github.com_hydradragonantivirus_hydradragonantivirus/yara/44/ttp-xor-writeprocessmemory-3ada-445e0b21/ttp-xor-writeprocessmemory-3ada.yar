rule TTP_XOR_WriteProcessMemory_3ada {
  strings:
    $key_3ada = { 6d a8 [2] 5f 8a [2] 59 bf [2] 77 bf [2] 48 a3 }

  condition:
    any of them
}