rule TTP_XOR_MULT_DOSStub_bfdf {
  strings:
    $key_bfdf = { eb b7 [2] 9f af [2] d8 ad [2] 9f bc [2] d1 b0 [2] dd ba [2] ca b1 [2] d1 ff [2] ec }

  condition:
    any of them
}