rule TTP_XOR_MULT_DOSStub_f0dd {
  strings:
    $key_f0dd = { a4 b5 [2] d0 ad [2] 97 af [2] d0 be [2] 9e b2 [2] 92 b8 [2] 85 b3 [2] 9e fd [2] a3 }

  condition:
    any of them
}