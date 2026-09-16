rule TTP_XOR_WriteProcessMemory_3def {
  strings:
    $key_3def = { 6a 9d [2] 58 bf [2] 5e 8a [2] 70 8a [2] 4f 96 }

  condition:
    any of them
}