rule TTP_XOR_WriteProcessMemory_d1dd {
  strings:
    $key_d1dd = { 86 af [2] b4 8d [2] b2 b8 [2] 9c b8 [2] a3 a4 }

  condition:
    any of them
}