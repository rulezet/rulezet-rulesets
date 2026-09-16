rule TTP_XOR_WriteProcessMemory_d59c {
  strings:
    $key_d59c = { 82 ee [2] b0 cc [2] b6 f9 [2] 98 f9 [2] a7 e5 }

  condition:
    any of them
}