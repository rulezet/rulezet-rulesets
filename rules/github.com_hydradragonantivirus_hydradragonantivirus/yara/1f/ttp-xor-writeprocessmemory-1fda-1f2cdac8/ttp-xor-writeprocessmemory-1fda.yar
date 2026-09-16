rule TTP_XOR_WriteProcessMemory_1fda {
  strings:
    $key_1fda = { 48 a8 [2] 7a 8a [2] 7c bf [2] 52 bf [2] 6d a3 }

  condition:
    any of them
}