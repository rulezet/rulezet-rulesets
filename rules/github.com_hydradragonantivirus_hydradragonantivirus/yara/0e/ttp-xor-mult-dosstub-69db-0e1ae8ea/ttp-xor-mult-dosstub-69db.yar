rule TTP_XOR_MULT_DOSStub_69db {
  strings:
    $key_69db = { 3d b3 [2] 49 ab [2] 0e a9 [2] 49 b8 [2] 07 b4 [2] 0b be [2] 1c b5 [2] 07 fb [2] 3a }

  condition:
    any of them
}