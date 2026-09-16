rule TTP_XOR_MULT_DOSStub_6fac {
  strings:
    $key_6fac = { 3b c4 [2] 4f dc [2] 08 de [2] 4f cf [2] 01 c3 [2] 0d c9 [2] 1a c2 [2] 01 8c [2] 3c }

  condition:
    any of them
}