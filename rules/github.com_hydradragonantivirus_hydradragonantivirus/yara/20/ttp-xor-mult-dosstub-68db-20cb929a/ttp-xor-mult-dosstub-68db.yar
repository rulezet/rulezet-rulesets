rule TTP_XOR_MULT_DOSStub_68db {
  strings:
    $key_68db = { 3c b3 [2] 48 ab [2] 0f a9 [2] 48 b8 [2] 06 b4 [2] 0a be [2] 1d b5 [2] 06 fb [2] 3b }

  condition:
    any of them
}