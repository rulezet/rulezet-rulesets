rule TTP_XOR_WriteProcessMemory_571c {
  strings:
    $key_571c = { 00 6e [2] 32 4c [2] 34 79 [2] 1a 79 [2] 25 65 }

  condition:
    any of them
}