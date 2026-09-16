rule TTP_XOR_WriteProcessMemory_d73b {
  strings:
    $key_d73b = { 80 49 [2] b2 6b [2] b4 5e [2] 9a 5e [2] a5 42 }

  condition:
    any of them
}