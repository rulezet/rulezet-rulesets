rule TTP_XOR_WriteProcessMemory_0b0e {
  strings:
    $key_0b0e = { 5c 7c [2] 6e 5e [2] 68 6b [2] 46 6b [2] 79 77 }

  condition:
    any of them
}