rule TTP_XOR_MULT_DOSStub_b9b8 {
  strings:
    $key_b9b8 = { ed d0 [2] 99 c8 [2] de ca [2] 99 db [2] d7 d7 [2] db dd [2] cc d6 [2] d7 98 [2] ea }

  condition:
    any of them
}