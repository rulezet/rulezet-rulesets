rule TTP_XOR_WriteProcessMemory_5c4e {
  strings:
    $key_5c4e = { 0b 3c [2] 39 1e [2] 3f 2b [2] 11 2b [2] 2e 37 }

  condition:
    any of them
}