rule TTP_XOR_MULT_DOSStub_26db {
  strings:
    $key_26db = { 72 b3 [2] 06 ab [2] 41 a9 [2] 06 b8 [2] 48 b4 [2] 44 be [2] 53 b5 [2] 48 fb [2] 75 }

  condition:
    any of them
}