rule TTP_XOR_WriteProcessMemory_165e {
  strings:
    $key_165e = { 41 2c [2] 73 0e [2] 75 3b [2] 5b 3b [2] 64 27 }

  condition:
    any of them
}