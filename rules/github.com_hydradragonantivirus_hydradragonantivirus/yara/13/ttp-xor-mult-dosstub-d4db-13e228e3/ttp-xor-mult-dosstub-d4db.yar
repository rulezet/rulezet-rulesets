rule TTP_XOR_MULT_DOSStub_d4db {
  strings:
    $key_d4db = { 80 b3 [2] f4 ab [2] b3 a9 [2] f4 b8 [2] ba b4 [2] b6 be [2] a1 b5 [2] ba fb [2] 87 }

  condition:
    any of them
}