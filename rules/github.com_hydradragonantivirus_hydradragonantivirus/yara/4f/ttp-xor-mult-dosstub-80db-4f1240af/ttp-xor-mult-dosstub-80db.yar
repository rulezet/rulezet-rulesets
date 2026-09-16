rule TTP_XOR_MULT_DOSStub_80db {
  strings:
    $key_80db = { d4 b3 [2] a0 ab [2] e7 a9 [2] a0 b8 [2] ee b4 [2] e2 be [2] f5 b5 [2] ee fb [2] d3 }

  condition:
    any of them
}