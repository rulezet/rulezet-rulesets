rule TTP_XOR_WriteProcessMemory_fbda {
  strings:
    $key_fbda = { ac a8 [2] 9e 8a [2] 98 bf [2] b6 bf [2] 89 a3 }

  condition:
    any of them
}