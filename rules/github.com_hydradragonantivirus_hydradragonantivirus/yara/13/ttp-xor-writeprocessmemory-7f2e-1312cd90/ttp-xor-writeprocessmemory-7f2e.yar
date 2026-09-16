rule TTP_XOR_WriteProcessMemory_7f2e {
  strings:
    $key_7f2e = { 28 5c [2] 1a 7e [2] 1c 4b [2] 32 4b [2] 0d 57 }

  condition:
    any of them
}