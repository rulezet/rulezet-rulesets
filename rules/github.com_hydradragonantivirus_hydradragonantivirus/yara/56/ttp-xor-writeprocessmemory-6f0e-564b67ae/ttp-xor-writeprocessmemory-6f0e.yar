rule TTP_XOR_WriteProcessMemory_6f0e {
  strings:
    $key_6f0e = { 38 7c [2] 0a 5e [2] 0c 6b [2] 22 6b [2] 1d 77 }

  condition:
    any of them
}