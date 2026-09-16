rule TTP_XOR_WriteProcessMemory_750e {
  strings:
    $key_750e = { 22 7c [2] 10 5e [2] 16 6b [2] 38 6b [2] 07 77 }

  condition:
    any of them
}