rule TTP_XOR_WriteProcessMemory_c49c {
  strings:
    $key_c49c = { 93 ee [2] a1 cc [2] a7 f9 [2] 89 f9 [2] b6 e5 }

  condition:
    any of them
}