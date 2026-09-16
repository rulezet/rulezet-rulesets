rule TTP_XOR_WriteProcessMemory_1cfb {
  strings:
    $key_1cfb = { 4b 89 [2] 79 ab [2] 7f 9e [2] 51 9e [2] 6e 82 }

  condition:
    any of them
}