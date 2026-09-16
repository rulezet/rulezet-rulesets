rule TTP_XOR_WriteProcessMemory_d7dd {
  strings:
    $key_d7dd = { 80 af [2] b2 8d [2] b4 b8 [2] 9a b8 [2] a5 a4 }

  condition:
    any of them
}