rule TTP_XOR_MULT_DOSStub_b9d3 {
  strings:
    $key_b9d3 = { ed bb [2] 99 a3 [2] de a1 [2] 99 b0 [2] d7 bc [2] db b6 [2] cc bd [2] d7 f3 [2] ea }

  condition:
    any of them
}