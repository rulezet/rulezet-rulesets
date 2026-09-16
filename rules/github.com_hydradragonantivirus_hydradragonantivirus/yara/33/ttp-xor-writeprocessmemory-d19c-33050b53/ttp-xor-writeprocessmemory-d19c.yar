rule TTP_XOR_WriteProcessMemory_d19c {
  strings:
    $key_d19c = { 86 ee [2] b4 cc [2] b2 f9 [2] 9c f9 [2] a3 e5 }

  condition:
    any of them
}