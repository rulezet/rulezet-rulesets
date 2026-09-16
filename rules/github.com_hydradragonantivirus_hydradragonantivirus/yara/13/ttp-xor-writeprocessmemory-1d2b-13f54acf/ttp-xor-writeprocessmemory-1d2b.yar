rule TTP_XOR_WriteProcessMemory_1d2b {
  strings:
    $key_1d2b = { 4a 59 [2] 78 7b [2] 7e 4e [2] 50 4e [2] 6f 52 }

  condition:
    any of them
}