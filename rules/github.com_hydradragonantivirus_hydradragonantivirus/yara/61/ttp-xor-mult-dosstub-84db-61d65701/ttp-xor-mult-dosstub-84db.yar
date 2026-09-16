rule TTP_XOR_MULT_DOSStub_84db {
  strings:
    $key_84db = { d0 b3 [2] a4 ab [2] e3 a9 [2] a4 b8 [2] ea b4 [2] e6 be [2] f1 b5 [2] ea fb [2] d7 }

  condition:
    any of them
}