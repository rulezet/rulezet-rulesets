rule TTP_XOR_WriteProcessMemory_6e4e {
  strings:
    $key_6e4e = { 39 3c [2] 0b 1e [2] 0d 2b [2] 23 2b [2] 1c 37 }

  condition:
    any of them
}