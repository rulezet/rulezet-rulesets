rule TTP_XOR_MULT_DOSStub_19db {
  strings:
    $key_19db = { 4d b3 [2] 39 ab [2] 7e a9 [2] 39 b8 [2] 77 b4 [2] 7b be [2] 6c b5 [2] 77 fb [2] 4a }

  condition:
    any of them
}