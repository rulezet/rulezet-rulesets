rule TTP_XOR_WriteProcessMemory_c5dd {
  strings:
    $key_c5dd = { 92 af [2] a0 8d [2] a6 b8 [2] 88 b8 [2] b7 a4 }

  condition:
    any of them
}