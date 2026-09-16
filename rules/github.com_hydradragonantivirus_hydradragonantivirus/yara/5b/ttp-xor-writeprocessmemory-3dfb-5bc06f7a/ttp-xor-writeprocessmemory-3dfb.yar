rule TTP_XOR_WriteProcessMemory_3dfb {
  strings:
    $key_3dfb = { 6a 89 [2] 58 ab [2] 5e 9e [2] 70 9e [2] 4f 82 }

  condition:
    any of them
}