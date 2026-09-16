rule TTP_XOR_WriteProcessMemory_7f4e {
  strings:
    $key_7f4e = { 28 3c [2] 1a 1e [2] 1c 2b [2] 32 2b [2] 0d 37 }

  condition:
    any of them
}