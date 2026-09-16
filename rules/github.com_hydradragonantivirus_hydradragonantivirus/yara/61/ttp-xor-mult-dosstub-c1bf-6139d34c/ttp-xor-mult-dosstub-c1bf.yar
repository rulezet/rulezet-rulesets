rule TTP_XOR_MULT_DOSStub_c1bf {
  strings:
    $key_c1bf = { 95 d7 [2] e1 cf [2] a6 cd [2] e1 dc [2] af d0 [2] a3 da [2] b4 d1 [2] af 9f [2] 92 }

  condition:
    any of them
}