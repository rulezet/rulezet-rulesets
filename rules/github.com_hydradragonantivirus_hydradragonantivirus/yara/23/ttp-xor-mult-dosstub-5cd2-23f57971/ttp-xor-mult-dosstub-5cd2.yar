rule TTP_XOR_MULT_DOSStub_5cd2 {
  strings:
    $key_5cd2 = { 08 ba [2] 7c a2 [2] 3b a0 [2] 7c b1 [2] 32 bd [2] 3e b7 [2] 29 bc [2] 32 f2 [2] 0f }

  condition:
    any of them
}