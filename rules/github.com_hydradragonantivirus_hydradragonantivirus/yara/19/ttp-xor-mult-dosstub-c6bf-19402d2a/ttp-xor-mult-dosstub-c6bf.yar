rule TTP_XOR_MULT_DOSStub_c6bf {
  strings:
    $key_c6bf = { 92 d7 [2] e6 cf [2] a1 cd [2] e6 dc [2] a8 d0 [2] a4 da [2] b3 d1 [2] a8 9f [2] 95 }

  condition:
    any of them
}