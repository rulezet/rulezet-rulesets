rule TTP_XOR_MULT_DOSStub_c0db {
  strings:
    $key_c0db = { 94 b3 [2] e0 ab [2] a7 a9 [2] e0 b8 [2] ae b4 [2] a2 be [2] b5 b5 [2] ae fb [2] 93 }

  condition:
    any of them
}