rule TTP_XOR_WriteProcessMemory_4d1e {
  strings:
    $key_4d1e = { 1a 6c [2] 28 4e [2] 2e 7b [2] 00 7b [2] 3f 67 }

  condition:
    any of them
}