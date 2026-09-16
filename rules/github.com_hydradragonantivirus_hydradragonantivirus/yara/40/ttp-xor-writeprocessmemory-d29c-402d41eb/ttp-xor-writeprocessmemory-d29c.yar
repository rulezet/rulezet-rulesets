rule TTP_XOR_WriteProcessMemory_d29c {
  strings:
    $key_d29c = { 85 ee [2] b7 cc [2] b1 f9 [2] 9f f9 [2] a0 e5 }

  condition:
    any of them
}