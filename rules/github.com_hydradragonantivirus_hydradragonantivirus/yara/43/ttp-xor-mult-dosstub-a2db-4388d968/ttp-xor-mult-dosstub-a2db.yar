rule TTP_XOR_MULT_DOSStub_a2db {
  strings:
    $key_a2db = { f6 b3 [2] 82 ab [2] c5 a9 [2] 82 b8 [2] cc b4 [2] c0 be [2] d7 b5 [2] cc fb [2] f1 }

  condition:
    any of them
}