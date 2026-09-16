rule TTP_XOR_WriteProcessMemory_4dfb {
  strings:
    $key_4dfb = { 1a 89 [2] 28 ab [2] 2e 9e [2] 00 9e [2] 3f 82 }

  condition:
    any of them
}