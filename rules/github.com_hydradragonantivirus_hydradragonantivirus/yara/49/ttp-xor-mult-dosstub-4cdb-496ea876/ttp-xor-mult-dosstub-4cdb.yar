rule TTP_XOR_MULT_DOSStub_4cdb {
  strings:
    $key_4cdb = { 18 b3 [2] 6c ab [2] 2b a9 [2] 6c b8 [2] 22 b4 [2] 2e be [2] 39 b5 [2] 22 fb [2] 1f }

  condition:
    any of them
}