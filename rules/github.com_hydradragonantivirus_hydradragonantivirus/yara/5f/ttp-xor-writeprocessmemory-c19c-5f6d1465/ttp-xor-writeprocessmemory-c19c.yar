rule TTP_XOR_WriteProcessMemory_c19c {
  strings:
    $key_c19c = { 96 ee [2] a4 cc [2] a2 f9 [2] 8c f9 [2] b3 e5 }

  condition:
    any of them
}