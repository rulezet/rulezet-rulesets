rule TTP_XOR_MULT_DOSStub_c4ad {
  strings:
    $key_c4ad = { 90 c5 [2] e4 dd [2] a3 df [2] e4 ce [2] aa c2 [2] a6 c8 [2] b1 c3 [2] aa 8d [2] 97 }

  condition:
    any of them
}