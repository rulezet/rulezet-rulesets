rule TTP_XOR_WriteProcessMemory_6cda {
  strings:
    $key_6cda = { 3b a8 [2] 09 8a [2] 0f bf [2] 21 bf [2] 1e a3 }

  condition:
    any of them
}