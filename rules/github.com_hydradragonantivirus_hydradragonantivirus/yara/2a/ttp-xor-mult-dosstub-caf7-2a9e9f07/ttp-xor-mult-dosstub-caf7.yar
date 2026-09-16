rule TTP_XOR_MULT_DOSStub_caf7 {
  strings:
    $key_caf7 = { 9e 9f [2] ea 87 [2] ad 85 [2] ea 94 [2] a4 98 [2] a8 92 [2] bf 99 [2] a4 d7 [2] 99 }

  condition:
    any of them
}