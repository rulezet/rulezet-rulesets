rule TTP_XOR_MULT_DOSStub_3fac {
  strings:
    $key_3fac = { 6b c4 [2] 1f dc [2] 58 de [2] 1f cf [2] 51 c3 [2] 5d c9 [2] 4a c2 [2] 51 8c [2] 6c }

  condition:
    any of them
}