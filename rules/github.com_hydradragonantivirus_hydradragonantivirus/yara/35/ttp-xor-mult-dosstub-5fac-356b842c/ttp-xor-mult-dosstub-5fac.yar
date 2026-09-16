rule TTP_XOR_MULT_DOSStub_5fac {
  strings:
    $key_5fac = { 0b c4 [2] 7f dc [2] 38 de [2] 7f cf [2] 31 c3 [2] 3d c9 [2] 2a c2 [2] 31 8c [2] 0c }

  condition:
    any of them
}