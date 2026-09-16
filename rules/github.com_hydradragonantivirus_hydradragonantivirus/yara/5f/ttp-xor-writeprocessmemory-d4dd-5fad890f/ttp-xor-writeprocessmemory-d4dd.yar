rule TTP_XOR_WriteProcessMemory_d4dd {
  strings:
    $key_d4dd = { 83 af [2] b1 8d [2] b7 b8 [2] 99 b8 [2] a6 a4 }

  condition:
    any of them
}