rule TTP_XOR_MULT_DOSStub_78db {
  strings:
    $key_78db = { 2c b3 [2] 58 ab [2] 1f a9 [2] 58 b8 [2] 16 b4 [2] 1a be [2] 0d b5 [2] 16 fb [2] 2b }

  condition:
    any of them
}