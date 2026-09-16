rule TTP_XOR_MULT_DOSStub_8add {
  strings:
    $key_8add = { de b5 [2] aa ad [2] ed af [2] aa be [2] e4 b2 [2] e8 b8 [2] ff b3 [2] e4 fd [2] d9 }

  condition:
    any of them
}