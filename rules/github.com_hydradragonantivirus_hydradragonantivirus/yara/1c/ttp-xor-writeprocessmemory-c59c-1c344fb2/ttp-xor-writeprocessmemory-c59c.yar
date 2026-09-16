rule TTP_XOR_WriteProcessMemory_c59c {
  strings:
    $key_c59c = { 92 ee [2] a0 cc [2] a6 f9 [2] 88 f9 [2] b7 e5 }

  condition:
    any of them
}