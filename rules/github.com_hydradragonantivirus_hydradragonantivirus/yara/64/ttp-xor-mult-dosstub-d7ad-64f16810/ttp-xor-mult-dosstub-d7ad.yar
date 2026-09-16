rule TTP_XOR_MULT_DOSStub_d7ad {
  strings:
    $key_d7ad = { 83 c5 [2] f7 dd [2] b0 df [2] f7 ce [2] b9 c2 [2] b5 c8 [2] a2 c3 [2] b9 8d [2] 84 }

  condition:
    any of them
}