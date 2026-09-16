rule TTP_XOR_MULT_DOSStub_3cd2 {
  strings:
    $key_3cd2 = { 68 ba [2] 1c a2 [2] 5b a0 [2] 1c b1 [2] 52 bd [2] 5e b7 [2] 49 bc [2] 52 f2 [2] 6f }

  condition:
    any of them
}