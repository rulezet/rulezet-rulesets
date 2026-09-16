rule TTP_XOR_MULT_DOSStub_7fac {
  strings:
    $key_7fac = { 2b c4 [2] 5f dc [2] 18 de [2] 5f cf [2] 11 c3 [2] 1d c9 [2] 0a c2 [2] 11 8c [2] 2c }

  condition:
    any of them
}