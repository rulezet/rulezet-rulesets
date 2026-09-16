rule TTP_XOR_WriteProcessMemory_0cda {
  strings:
    $key_0cda = { 5b a8 [2] 69 8a [2] 6f bf [2] 41 bf [2] 7e a3 }

  condition:
    any of them
}