rule TTP_XOR_MULT_DOSStub_7cdb {
  strings:
    $key_7cdb = { 28 b3 [2] 5c ab [2] 1b a9 [2] 5c b8 [2] 12 b4 [2] 1e be [2] 09 b5 [2] 12 fb [2] 2f }

  condition:
    any of them
}