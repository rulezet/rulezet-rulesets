rule TTP_XOR_MULT_DOSStub_fbb8 {
  strings:
    $key_fbb8 = { af d0 [2] db c8 [2] 9c ca [2] db db [2] 95 d7 [2] 99 dd [2] 8e d6 [2] 95 98 [2] a8 }

  condition:
    any of them
}