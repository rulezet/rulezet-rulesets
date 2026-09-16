rule TTP_XOR_WriteProcessMemory_5fda {
  strings:
    $key_5fda = { 08 a8 [2] 3a 8a [2] 3c bf [2] 12 bf [2] 2d a3 }

  condition:
    any of them
}