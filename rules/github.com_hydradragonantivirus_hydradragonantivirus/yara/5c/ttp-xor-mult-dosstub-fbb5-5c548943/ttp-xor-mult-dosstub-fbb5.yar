rule TTP_XOR_MULT_DOSStub_fbb5 {
  strings:
    $key_fbb5 = { af dd [2] db c5 [2] 9c c7 [2] db d6 [2] 95 da [2] 99 d0 [2] 8e db [2] 95 95 [2] a8 }

  condition:
    any of them
}