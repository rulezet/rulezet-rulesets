rule TTP_XOR_WriteProcessMemory_1cda {
  strings:
    $key_1cda = { 4b a8 [2] 79 8a [2] 7f bf [2] 51 bf [2] 6e a3 }

  condition:
    any of them
}