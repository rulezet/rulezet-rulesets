rule TTP_XOR_WriteProcessMemory_1dfb {
  strings:
    $key_1dfb = { 4a 89 [2] 78 ab [2] 7e 9e [2] 50 9e [2] 6f 82 }

  condition:
    any of them
}