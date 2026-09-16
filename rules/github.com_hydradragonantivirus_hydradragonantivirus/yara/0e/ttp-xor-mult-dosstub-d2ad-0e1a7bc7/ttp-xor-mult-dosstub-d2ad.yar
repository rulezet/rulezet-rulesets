rule TTP_XOR_MULT_DOSStub_d2ad {
  strings:
    $key_d2ad = { 86 c5 [2] f2 dd [2] b5 df [2] f2 ce [2] bc c2 [2] b0 c8 [2] a7 c3 [2] bc 8d [2] 81 }

  condition:
    any of them
}