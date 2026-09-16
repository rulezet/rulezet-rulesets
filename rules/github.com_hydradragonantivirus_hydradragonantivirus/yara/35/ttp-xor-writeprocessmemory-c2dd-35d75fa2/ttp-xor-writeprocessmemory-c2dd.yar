rule TTP_XOR_WriteProcessMemory_c2dd {
  strings:
    $key_c2dd = { 95 af [2] a7 8d [2] a1 b8 [2] 8f b8 [2] b0 a4 }

  condition:
    any of them
}