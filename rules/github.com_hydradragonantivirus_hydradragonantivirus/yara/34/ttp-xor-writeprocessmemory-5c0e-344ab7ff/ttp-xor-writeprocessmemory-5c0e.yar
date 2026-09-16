rule TTP_XOR_WriteProcessMemory_5c0e {
  strings:
    $key_5c0e = { 0b 7c [2] 39 5e [2] 3f 6b [2] 11 6b [2] 2e 77 }

  condition:
    any of them
}