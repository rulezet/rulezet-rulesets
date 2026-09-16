rule TTP_XOR_MULT_DOSStub_90b8 {
  strings:
    $key_90b8 = { c4 d0 [2] b0 c8 [2] f7 ca [2] b0 db [2] fe d7 [2] f2 dd [2] e5 d6 [2] fe 98 [2] c3 }

  condition:
    any of them
}