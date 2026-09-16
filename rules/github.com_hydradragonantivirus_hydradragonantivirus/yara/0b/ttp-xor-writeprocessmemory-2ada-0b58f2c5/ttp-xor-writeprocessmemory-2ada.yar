rule TTP_XOR_WriteProcessMemory_2ada {
  strings:
    $key_2ada = { 7d a8 [2] 4f 8a [2] 49 bf [2] 67 bf [2] 58 a3 }

  condition:
    any of them
}