rule TTP_XOR_WriteProcessMemory_7b2b {
  strings:
    $key_7b2b = { 2c 59 [2] 1e 7b [2] 18 4e [2] 36 4e [2] 09 52 }

  condition:
    any of them
}