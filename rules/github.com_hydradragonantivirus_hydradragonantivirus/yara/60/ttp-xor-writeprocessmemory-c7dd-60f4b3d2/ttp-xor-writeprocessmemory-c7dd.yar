rule TTP_XOR_WriteProcessMemory_c7dd {
  strings:
    $key_c7dd = { 90 af [2] a2 8d [2] a4 b8 [2] 8a b8 [2] b5 a4 }

  condition:
    any of them
}