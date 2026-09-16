rule TTP_XOR_MULT_DOSStub_a0db {
  strings:
    $key_a0db = { f4 b3 [2] 80 ab [2] c7 a9 [2] 80 b8 [2] ce b4 [2] c2 be [2] d5 b5 [2] ce fb [2] f3 }

  condition:
    any of them
}