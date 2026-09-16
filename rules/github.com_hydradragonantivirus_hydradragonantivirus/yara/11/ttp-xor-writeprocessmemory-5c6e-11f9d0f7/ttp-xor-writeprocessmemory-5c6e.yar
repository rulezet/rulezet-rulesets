rule TTP_XOR_WriteProcessMemory_5c6e {
  strings:
    $key_5c6e = { 0b 1c [2] 39 3e [2] 3f 0b [2] 11 0b [2] 2e 17 }

  condition:
    any of them
}