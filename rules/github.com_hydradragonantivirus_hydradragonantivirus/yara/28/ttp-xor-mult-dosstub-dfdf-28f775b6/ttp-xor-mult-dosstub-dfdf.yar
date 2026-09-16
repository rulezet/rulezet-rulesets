rule TTP_XOR_MULT_DOSStub_dfdf {
  strings:
    $key_dfdf = { 8b b7 [2] ff af [2] b8 ad [2] ff bc [2] b1 b0 [2] bd ba [2] aa b1 [2] b1 ff [2] 8c }

  condition:
    any of them
}