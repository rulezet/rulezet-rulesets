rule TTP_XOR_WriteProcessMemory_2fda {
  strings:
    $key_2fda = { 78 a8 [2] 4a 8a [2] 4c bf [2] 62 bf [2] 5d a3 }

  condition:
    any of them
}