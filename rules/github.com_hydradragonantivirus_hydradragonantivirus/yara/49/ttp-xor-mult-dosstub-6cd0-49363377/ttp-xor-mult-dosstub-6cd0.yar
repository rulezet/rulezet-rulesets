rule TTP_XOR_MULT_DOSStub_6cd0 {
  strings:
    $key_6cd0 = { 38 b8 [2] 4c a0 [2] 0b a2 [2] 4c b3 [2] 02 bf [2] 0e b5 [2] 19 be [2] 02 f0 [2] 3f }

  condition:
    any of them
}