rule TTP_XOR_MULT_DOSStub_c6bd {
  strings:
    $key_c6bd = { 92 d5 [2] e6 cd [2] a1 cf [2] e6 de [2] a8 d2 [2] a4 d8 [2] b3 d3 [2] a8 9d [2] 95 }

  condition:
    any of them
}