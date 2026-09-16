rule TTP_XOR_MULT_DOSStub_abdf {
  strings:
    $key_abdf = { ff b7 [2] 8b af [2] cc ad [2] 8b bc [2] c5 b0 [2] c9 ba [2] de b1 [2] c5 ff [2] f8 }

  condition:
    any of them
}