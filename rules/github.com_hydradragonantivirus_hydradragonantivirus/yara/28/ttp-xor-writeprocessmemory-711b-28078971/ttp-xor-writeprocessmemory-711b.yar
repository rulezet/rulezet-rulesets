rule TTP_XOR_WriteProcessMemory_711b {
  strings:
    $key_711b = { 26 69 [2] 14 4b [2] 12 7e [2] 3c 7e [2] 03 62 }

  condition:
    any of them
}