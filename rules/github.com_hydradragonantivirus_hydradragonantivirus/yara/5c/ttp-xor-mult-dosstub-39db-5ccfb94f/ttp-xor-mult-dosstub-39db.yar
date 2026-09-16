rule TTP_XOR_MULT_DOSStub_39db {
  strings:
    $key_39db = { 6d b3 [2] 19 ab [2] 5e a9 [2] 19 b8 [2] 57 b4 [2] 5b be [2] 4c b5 [2] 57 fb [2] 6a }

  condition:
    any of them
}