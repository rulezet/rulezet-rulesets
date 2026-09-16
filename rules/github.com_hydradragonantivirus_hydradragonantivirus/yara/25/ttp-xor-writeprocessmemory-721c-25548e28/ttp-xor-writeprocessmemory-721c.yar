rule TTP_XOR_WriteProcessMemory_721c {
  strings:
    $key_721c = { 25 6e [2] 17 4c [2] 11 79 [2] 3f 79 [2] 00 65 }

  condition:
    any of them
}