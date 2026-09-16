rule TTP_XOR_WriteProcessMemory_714e {
  strings:
    $key_714e = { 26 3c [2] 14 1e [2] 12 2b [2] 3c 2b [2] 03 37 }

  condition:
    any of them
}