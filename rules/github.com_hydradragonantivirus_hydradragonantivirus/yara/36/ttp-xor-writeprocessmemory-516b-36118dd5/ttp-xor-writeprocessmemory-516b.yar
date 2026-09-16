rule TTP_XOR_WriteProcessMemory_516b {
  strings:
    $key_516b = { 06 19 [2] 34 3b [2] 32 0e [2] 1c 0e [2] 23 12 }

  condition:
    any of them
}