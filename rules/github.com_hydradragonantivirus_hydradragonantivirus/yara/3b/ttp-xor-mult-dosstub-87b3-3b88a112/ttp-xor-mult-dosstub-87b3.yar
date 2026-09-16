rule TTP_XOR_MULT_DOSStub_87b3 {
  strings:
    $key_87b3 = { d3 db [2] a7 c3 [2] e0 c1 [2] a7 d0 [2] e9 dc [2] e5 d6 [2] f2 dd [2] e9 93 [2] d4 }

  condition:
    any of them
}