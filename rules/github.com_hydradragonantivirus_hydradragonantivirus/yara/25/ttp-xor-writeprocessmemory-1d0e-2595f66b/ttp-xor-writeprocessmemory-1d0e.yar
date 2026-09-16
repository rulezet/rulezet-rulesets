rule TTP_XOR_WriteProcessMemory_1d0e {
  strings:
    $key_1d0e = { 4a 7c [2] 78 5e [2] 7e 6b [2] 50 6b [2] 6f 77 }

  condition:
    any of them
}