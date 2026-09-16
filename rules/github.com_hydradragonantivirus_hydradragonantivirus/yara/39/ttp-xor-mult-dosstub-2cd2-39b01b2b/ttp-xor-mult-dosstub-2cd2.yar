rule TTP_XOR_MULT_DOSStub_2cd2 {
  strings:
    $key_2cd2 = { 78 ba [2] 0c a2 [2] 4b a0 [2] 0c b1 [2] 42 bd [2] 4e b7 [2] 59 bc [2] 42 f2 [2] 7f }

  condition:
    any of them
}