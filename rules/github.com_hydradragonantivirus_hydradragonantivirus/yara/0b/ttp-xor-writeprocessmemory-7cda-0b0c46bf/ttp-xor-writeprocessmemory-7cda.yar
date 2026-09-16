rule TTP_XOR_WriteProcessMemory_7cda {
  strings:
    $key_7cda = { 2b a8 [2] 19 8a [2] 1f bf [2] 31 bf [2] 0e a3 }

  condition:
    any of them
}