rule TTP_XOR_WriteProcessMemory_772d {
  strings:
    $key_772d = { 20 5f [2] 12 7d [2] 14 48 [2] 3a 48 [2] 05 54 }

  condition:
    any of them
}