rule TTP_XOR_MULT_DOSStub_f0db {
  strings:
    $key_f0db = { a4 b3 [2] d0 ab [2] 97 a9 [2] d0 b8 [2] 9e b4 [2] 92 be [2] 85 b5 [2] 9e fb [2] a3 }

  condition:
    any of them
}