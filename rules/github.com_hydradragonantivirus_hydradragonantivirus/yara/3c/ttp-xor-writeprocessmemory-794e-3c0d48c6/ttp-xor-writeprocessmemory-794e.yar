rule TTP_XOR_WriteProcessMemory_794e {
  strings:
    $key_794e = { 2e 3c [2] 1c 1e [2] 1a 2b [2] 34 2b [2] 0b 37 }

  condition:
    any of them
}