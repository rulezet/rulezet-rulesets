rule TTP_XOR_WriteProcessMemory_710e {
  strings:
    $key_710e = { 26 7c [2] 14 5e [2] 12 6b [2] 3c 6b [2] 03 77 }

  condition:
    any of them
}