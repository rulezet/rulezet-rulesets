rule TTP_XOR_WriteProcessMemory_764e {
  strings:
    $key_764e = { 21 3c [2] 13 1e [2] 15 2b [2] 3b 2b [2] 04 37 }

  condition:
    any of them
}