rule TTP_XOR_WriteProcessMemory_0dfb {
  strings:
    $key_0dfb = { 5a 89 [2] 68 ab [2] 6e 9e [2] 40 9e [2] 7f 82 }

  condition:
    any of them
}