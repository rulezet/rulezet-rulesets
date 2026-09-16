rule TTP_XOR_WriteProcessMemory_636e {
  strings:
    $key_636e = { 34 1c [2] 06 3e [2] 00 0b [2] 2e 0b [2] 11 17 }

  condition:
    any of them
}