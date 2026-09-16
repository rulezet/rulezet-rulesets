rule TTP_XOR_MULT_DOSStub_79db {
  strings:
    $key_79db = { 2d b3 [2] 59 ab [2] 1e a9 [2] 59 b8 [2] 17 b4 [2] 1b be [2] 0c b5 [2] 17 fb [2] 2a }

  condition:
    any of them
}