rule TTP_XOR_WriteProcessMemory_d10b {
  strings:
    $key_d10b = { 86 79 [2] b4 5b [2] b2 6e [2] 9c 6e [2] a3 72 }

  condition:
    any of them
}