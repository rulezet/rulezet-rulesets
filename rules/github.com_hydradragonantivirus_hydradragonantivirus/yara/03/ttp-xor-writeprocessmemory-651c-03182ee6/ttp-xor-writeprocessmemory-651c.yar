rule TTP_XOR_WriteProcessMemory_651c {
  strings:
    $key_651c = { 32 6e [2] 00 4c [2] 06 79 [2] 28 79 [2] 17 65 }

  condition:
    any of them
}