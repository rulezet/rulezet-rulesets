rule TTP_XOR_MULT_DOSStub_aedd {
  strings:
    $key_aedd = { fa b5 [2] 8e ad [2] c9 af [2] 8e be [2] c0 b2 [2] cc b8 [2] db b3 [2] c0 fd [2] fd }

  condition:
    any of them
}