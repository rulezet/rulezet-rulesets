rule TTP_XOR_MULT_DOSStub_b9c1 {
  strings:
    $key_b9c1 = { ed a9 [2] 99 b1 [2] de b3 [2] 99 a2 [2] d7 ae [2] db a4 [2] cc af [2] d7 e1 [2] ea }

  condition:
    any of them
}