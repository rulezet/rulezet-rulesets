rule TTP_XOR_WriteProcessMemory_616b {
  strings:
    $key_616b = { 36 19 [2] 04 3b [2] 02 0e [2] 2c 0e [2] 13 12 }

  condition:
    any of them
}