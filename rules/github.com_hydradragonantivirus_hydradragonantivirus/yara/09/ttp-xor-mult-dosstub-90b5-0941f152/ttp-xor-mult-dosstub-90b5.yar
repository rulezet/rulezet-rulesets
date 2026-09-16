rule TTP_XOR_MULT_DOSStub_90b5 {
  strings:
    $key_90b5 = { c4 dd [2] b0 c5 [2] f7 c7 [2] b0 d6 [2] fe da [2] f2 d0 [2] e5 db [2] fe 95 [2] c3 }

  condition:
    any of them
}