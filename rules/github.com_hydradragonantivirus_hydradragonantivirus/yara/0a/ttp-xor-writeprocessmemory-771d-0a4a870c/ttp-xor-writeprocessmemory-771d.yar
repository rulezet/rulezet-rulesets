rule TTP_XOR_WriteProcessMemory_771d {
  strings:
    $key_771d = { 20 6f [2] 12 4d [2] 14 78 [2] 3a 78 [2] 05 64 }

  condition:
    any of them
}