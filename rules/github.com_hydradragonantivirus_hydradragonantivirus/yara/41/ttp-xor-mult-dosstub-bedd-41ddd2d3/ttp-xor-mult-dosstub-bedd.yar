rule TTP_XOR_MULT_DOSStub_bedd {
  strings:
    $key_bedd = { ea b5 [2] 9e ad [2] d9 af [2] 9e be [2] d0 b2 [2] dc b8 [2] cb b3 [2] d0 fd [2] ed }

  condition:
    any of them
}