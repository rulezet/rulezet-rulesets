rule TTP_XOR_WriteProcessMemory_631e {
  strings:
    $key_631e = { 34 6c [2] 06 4e [2] 00 7b [2] 2e 7b [2] 11 67 }

  condition:
    any of them
}