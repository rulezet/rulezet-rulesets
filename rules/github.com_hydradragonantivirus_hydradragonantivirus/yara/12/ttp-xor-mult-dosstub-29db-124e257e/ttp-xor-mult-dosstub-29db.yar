rule TTP_XOR_MULT_DOSStub_29db {
  strings:
    $key_29db = { 7d b3 [2] 09 ab [2] 4e a9 [2] 09 b8 [2] 47 b4 [2] 4b be [2] 5c b5 [2] 47 fb [2] 7a }

  condition:
    any of them
}