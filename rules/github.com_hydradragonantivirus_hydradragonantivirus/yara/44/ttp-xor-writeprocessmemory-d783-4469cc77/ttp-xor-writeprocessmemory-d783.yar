rule TTP_XOR_WriteProcessMemory_d783 {
  strings:
    $key_d783 = { 80 f1 [2] b2 d3 [2] b4 e6 [2] 9a e6 [2] a5 fa }

  condition:
    any of them
}