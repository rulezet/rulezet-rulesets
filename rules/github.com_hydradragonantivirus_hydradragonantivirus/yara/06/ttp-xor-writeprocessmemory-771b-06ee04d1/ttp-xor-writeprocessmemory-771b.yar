rule TTP_XOR_WriteProcessMemory_771b {
  strings:
    $key_771b = { 20 69 [2] 12 4b [2] 14 7e [2] 3a 7e [2] 05 62 }

  condition:
    any of them
}