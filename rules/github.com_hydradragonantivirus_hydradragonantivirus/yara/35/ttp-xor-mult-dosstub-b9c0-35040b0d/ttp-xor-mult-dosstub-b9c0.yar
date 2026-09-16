rule TTP_XOR_MULT_DOSStub_b9c0 {
  strings:
    $key_b9c0 = { ed a8 [2] 99 b0 [2] de b2 [2] 99 a3 [2] d7 af [2] db a5 [2] cc ae [2] d7 e0 [2] ea }

  condition:
    any of them
}