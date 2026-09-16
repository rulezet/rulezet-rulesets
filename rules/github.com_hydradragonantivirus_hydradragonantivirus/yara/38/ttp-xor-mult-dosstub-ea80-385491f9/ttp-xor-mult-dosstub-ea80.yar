rule TTP_XOR_MULT_DOSStub_ea80 {
  strings:
    $key_ea80 = { be e8 [2] ca f0 [2] 8d f2 [2] ca e3 [2] 84 ef [2] 88 e5 [2] 9f ee [2] 84 a0 [2] b9 }

  condition:
    any of them
}