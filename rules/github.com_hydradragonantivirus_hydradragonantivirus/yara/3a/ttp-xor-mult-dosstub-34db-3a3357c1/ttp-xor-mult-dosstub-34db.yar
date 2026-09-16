rule TTP_XOR_MULT_DOSStub_34db {
  strings:
    $key_34db = { 60 b3 [2] 14 ab [2] 53 a9 [2] 14 b8 [2] 5a b4 [2] 56 be [2] 41 b5 [2] 5a fb [2] 67 }

  condition:
    any of them
}