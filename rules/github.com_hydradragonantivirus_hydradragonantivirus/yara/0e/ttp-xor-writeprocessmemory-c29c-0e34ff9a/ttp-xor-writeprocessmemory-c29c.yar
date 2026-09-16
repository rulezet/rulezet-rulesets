rule TTP_XOR_WriteProcessMemory_c29c {
  strings:
    $key_c29c = { 95 ee [2] a7 cc [2] a1 f9 [2] 8f f9 [2] b0 e5 }

  condition:
    any of them
}