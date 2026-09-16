rule TTP_XOR_MULT_DOSStub_8adf {
  strings:
    $key_8adf = { de b7 [2] aa af [2] ed ad [2] aa bc [2] e4 b0 [2] e8 ba [2] ff b1 [2] e4 ff [2] d9 }

  condition:
    any of them
}