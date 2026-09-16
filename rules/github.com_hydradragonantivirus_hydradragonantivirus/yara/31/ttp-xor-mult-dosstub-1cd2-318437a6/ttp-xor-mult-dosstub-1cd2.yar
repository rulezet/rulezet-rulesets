rule TTP_XOR_MULT_DOSStub_1cd2 {
  strings:
    $key_1cd2 = { 48 ba [2] 3c a2 [2] 7b a0 [2] 3c b1 [2] 72 bd [2] 7e b7 [2] 69 bc [2] 72 f2 [2] 4f }

  condition:
    any of them
}