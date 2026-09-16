rule TTP_XOR_MULT_DOSStub_28db {
  strings:
    $key_28db = { 7c b3 [2] 08 ab [2] 4f a9 [2] 08 b8 [2] 46 b4 [2] 4a be [2] 5d b5 [2] 46 fb [2] 7b }

  condition:
    any of them
}