rule TTP_XOR_WriteProcessMemory_d65b {
  strings:
    $key_d65b = { 81 29 [2] b3 0b [2] b5 3e [2] 9b 3e [2] a4 22 }

  condition:
    any of them
}