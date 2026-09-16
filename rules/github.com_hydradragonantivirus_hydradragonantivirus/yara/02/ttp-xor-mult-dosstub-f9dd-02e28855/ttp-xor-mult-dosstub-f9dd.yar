rule TTP_XOR_MULT_DOSStub_f9dd {
  strings:
    $key_f9dd = { ad b5 [2] d9 ad [2] 9e af [2] d9 be [2] 97 b2 [2] 9b b8 [2] 8c b3 [2] 97 fd [2] aa }

  condition:
    any of them
}