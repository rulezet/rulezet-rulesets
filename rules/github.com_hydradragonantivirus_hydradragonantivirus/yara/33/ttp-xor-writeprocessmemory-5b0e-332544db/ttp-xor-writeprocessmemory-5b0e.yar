rule TTP_XOR_WriteProcessMemory_5b0e {
  strings:
    $key_5b0e = { 0c 7c [2] 3e 5e [2] 38 6b [2] 16 6b [2] 29 77 }

  condition:
    any of them
}