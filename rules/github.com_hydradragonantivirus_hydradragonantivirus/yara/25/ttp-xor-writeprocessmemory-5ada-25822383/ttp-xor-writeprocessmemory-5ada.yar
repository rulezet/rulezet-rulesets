rule TTP_XOR_WriteProcessMemory_5ada {
  strings:
    $key_5ada = { 0d a8 [2] 3f 8a [2] 39 bf [2] 17 bf [2] 28 a3 }

  condition:
    any of them
}