rule TTP_XOR_WriteProcessMemory_2bda {
  strings:
    $key_2bda = { 7c a8 [2] 4e 8a [2] 48 bf [2] 66 bf [2] 59 a3 }

  condition:
    any of them
}