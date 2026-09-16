rule TTP_XOR_WriteProcessMemory_5cfb {
  strings:
    $key_5cfb = { 0b 89 [2] 39 ab [2] 3f 9e [2] 11 9e [2] 2e 82 }

  condition:
    any of them
}