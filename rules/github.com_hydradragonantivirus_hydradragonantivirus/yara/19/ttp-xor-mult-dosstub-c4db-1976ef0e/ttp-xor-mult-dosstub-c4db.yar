rule TTP_XOR_MULT_DOSStub_c4db {
  strings:
    $key_c4db = { 90 b3 [2] e4 ab [2] a3 a9 [2] e4 b8 [2] aa b4 [2] a6 be [2] b1 b5 [2] aa fb [2] 97 }

  condition:
    any of them
}