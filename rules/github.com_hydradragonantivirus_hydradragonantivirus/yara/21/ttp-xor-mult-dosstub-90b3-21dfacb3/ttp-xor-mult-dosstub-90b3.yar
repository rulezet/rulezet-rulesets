rule TTP_XOR_MULT_DOSStub_90b3 {
  strings:
    $key_90b3 = { c4 db [2] b0 c3 [2] f7 c1 [2] b0 d0 [2] fe dc [2] f2 d6 [2] e5 dd [2] fe 93 [2] c3 }

  condition:
    any of them
}