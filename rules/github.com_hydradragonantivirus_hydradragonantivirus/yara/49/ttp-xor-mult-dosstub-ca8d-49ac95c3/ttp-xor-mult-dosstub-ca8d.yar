rule TTP_XOR_MULT_DOSStub_ca8d {
  strings:
    $key_ca8d = { 9e e5 [2] ea fd [2] ad ff [2] ea ee [2] a4 e2 [2] a8 e8 [2] bf e3 [2] a4 ad [2] 99 }

  condition:
    any of them
}