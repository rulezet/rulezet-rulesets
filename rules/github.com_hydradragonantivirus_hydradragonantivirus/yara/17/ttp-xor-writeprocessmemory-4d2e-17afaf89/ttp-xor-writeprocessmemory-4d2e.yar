rule TTP_XOR_WriteProcessMemory_4d2e {
  strings:
    $key_4d2e = { 1a 5c [2] 28 7e [2] 2e 4b [2] 00 4b [2] 3f 57 }

  condition:
    any of them
}