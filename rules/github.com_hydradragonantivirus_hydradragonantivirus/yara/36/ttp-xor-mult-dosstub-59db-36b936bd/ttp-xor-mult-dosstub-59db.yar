rule TTP_XOR_MULT_DOSStub_59db {
  strings:
    $key_59db = { 0d b3 [2] 79 ab [2] 3e a9 [2] 79 b8 [2] 37 b4 [2] 3b be [2] 2c b5 [2] 37 fb [2] 0a }

  condition:
    any of them
}