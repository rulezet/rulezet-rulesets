rule TTP_XOR_WriteProcessMemory_4d0e {
  strings:
    $key_4d0e = { 1a 7c [2] 28 5e [2] 2e 6b [2] 00 6b [2] 3f 77 }

  condition:
    any of them
}