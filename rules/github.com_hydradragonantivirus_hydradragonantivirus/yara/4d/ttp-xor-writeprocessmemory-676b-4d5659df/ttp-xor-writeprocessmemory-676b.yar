rule TTP_XOR_WriteProcessMemory_676b {
  strings:
    $key_676b = { 30 19 [2] 02 3b [2] 04 0e [2] 2a 0e [2] 15 12 }

  condition:
    any of them
}