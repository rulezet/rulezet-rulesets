rule TTP_XOR_WriteProcessMemory_5f2e {
  strings:
    $key_5f2e = { 08 5c [2] 3a 7e [2] 3c 4b [2] 12 4b [2] 2d 57 }

  condition:
    any of them
}