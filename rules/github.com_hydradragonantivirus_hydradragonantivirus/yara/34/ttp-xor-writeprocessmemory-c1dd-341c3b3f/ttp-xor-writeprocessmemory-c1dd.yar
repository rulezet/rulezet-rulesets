rule TTP_XOR_WriteProcessMemory_c1dd {
  strings:
    $key_c1dd = { 96 af [2] a4 8d [2] a2 b8 [2] 8c b8 [2] b3 a4 }

  condition:
    any of them
}