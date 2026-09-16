rule TTP_XOR_WriteProcessMemory_1d1b {
  strings:
    $key_1d1b = { 4a 69 [2] 78 4b [2] 7e 7e [2] 50 7e [2] 6f 62 }

  condition:
    any of them
}