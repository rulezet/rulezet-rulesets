rule TTP_XOR_MULT_DOSStub_49db {
  strings:
    $key_49db = { 1d b3 [2] 69 ab [2] 2e a9 [2] 69 b8 [2] 27 b4 [2] 2b be [2] 3c b5 [2] 27 fb [2] 1a }

  condition:
    any of them
}