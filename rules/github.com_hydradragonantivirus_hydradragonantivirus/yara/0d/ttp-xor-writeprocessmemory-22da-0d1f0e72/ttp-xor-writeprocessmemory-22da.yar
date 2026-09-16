rule TTP_XOR_WriteProcessMemory_22da {
  strings:
    $key_22da = { 75 a8 [2] 47 8a [2] 41 bf [2] 6f bf [2] 50 a3 }

  condition:
    any of them
}