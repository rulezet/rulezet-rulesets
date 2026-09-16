rule TTP_XOR_MULT_DOSStub_93db {
  strings:
    $key_93db = { c7 b3 [2] b3 ab [2] f4 a9 [2] b3 b8 [2] fd b4 [2] f1 be [2] e6 b5 [2] fd fb [2] c0 }

  condition:
    any of them
}