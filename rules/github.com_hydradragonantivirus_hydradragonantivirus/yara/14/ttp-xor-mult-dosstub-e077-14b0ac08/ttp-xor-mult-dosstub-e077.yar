rule TTP_XOR_MULT_DOSStub_e077 {
  strings:
    $key_e077 = { b4 1f [2] c0 07 [2] 87 05 [2] c0 14 [2] 8e 18 [2] 82 12 [2] 95 19 [2] 8e 57 [2] b3 }

  condition:
    any of them
}