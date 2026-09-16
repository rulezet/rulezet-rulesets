rule TTP_XOR_WriteProcessMemory_7b1b {
  strings:
    $key_7b1b = { 2c 69 [2] 1e 4b [2] 18 7e [2] 36 7e [2] 09 62 }

  condition:
    any of them
}