rule TTP_XOR_MULT_DOSStub_b9c3 {
  strings:
    $key_b9c3 = { ed ab [2] 99 b3 [2] de b1 [2] 99 a0 [2] d7 ac [2] db a6 [2] cc ad [2] d7 e3 [2] ea }

  condition:
    any of them
}