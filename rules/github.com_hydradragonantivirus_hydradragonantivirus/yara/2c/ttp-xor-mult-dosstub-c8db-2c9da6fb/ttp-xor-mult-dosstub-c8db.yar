rule TTP_XOR_MULT_DOSStub_c8db {
  strings:
    $key_c8db = { 9c b3 [2] e8 ab [2] af a9 [2] e8 b8 [2] a6 b4 [2] aa be [2] bd b5 [2] a6 fb [2] 9b }

  condition:
    any of them
}