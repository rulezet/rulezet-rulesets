rule TTP_XOR_MULT_DOSStub_d0ad {
  strings:
    $key_d0ad = { 84 c5 [2] f0 dd [2] b7 df [2] f0 ce [2] be c2 [2] b2 c8 [2] a5 c3 [2] be 8d [2] 83 }

  condition:
    any of them
}