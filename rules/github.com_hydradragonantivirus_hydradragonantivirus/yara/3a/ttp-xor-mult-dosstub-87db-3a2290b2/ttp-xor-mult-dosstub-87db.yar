rule TTP_XOR_MULT_DOSStub_87db {
  strings:
    $key_87db = { d3 b3 [2] a7 ab [2] e0 a9 [2] a7 b8 [2] e9 b4 [2] e5 be [2] f2 b5 [2] e9 fb [2] d4 }

  condition:
    any of them
}