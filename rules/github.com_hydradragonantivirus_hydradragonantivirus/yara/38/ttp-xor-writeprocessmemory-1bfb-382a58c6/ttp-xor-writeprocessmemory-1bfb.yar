rule TTP_XOR_WriteProcessMemory_1bfb {
  strings:
    $key_1bfb = { 4c 89 [2] 7e ab [2] 78 9e [2] 56 9e [2] 69 82 }

  condition:
    any of them
}