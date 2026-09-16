rule TTP_XOR_MULT_DOSStub_d2b8 {
  strings:
    $key_d2b8 = { 86 d0 [2] f2 c8 [2] b5 ca [2] f2 db [2] bc d7 [2] b0 dd [2] a7 d6 [2] bc 98 [2] 81 }

  condition:
    any of them
}