rule TTP_XOR_WriteProcessMemory_c0dd {
  strings:
    $key_c0dd = { 97 af [2] a5 8d [2] a3 b8 [2] 8d b8 [2] b2 a4 }

  condition:
    any of them
}