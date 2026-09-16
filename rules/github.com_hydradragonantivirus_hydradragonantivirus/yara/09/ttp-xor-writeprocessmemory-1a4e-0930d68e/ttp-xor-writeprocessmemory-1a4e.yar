rule TTP_XOR_WriteProcessMemory_1a4e {
  strings:
    $key_1a4e = { 4d 3c [2] 7f 1e [2] 79 2b [2] 57 2b [2] 68 37 }

  condition:
    any of them
}