rule TTP_XOR_WriteProcessMemory_610b {
  strings:
    $key_610b = { 36 79 [2] 04 5b [2] 02 6e [2] 2c 6e [2] 13 72 }

  condition:
    any of them
}