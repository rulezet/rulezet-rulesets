rule TTP_XOR_MULT_DOSStub_2cd4 {
  strings:
    $key_2cd4 = { 78 bc [2] 0c a4 [2] 4b a6 [2] 0c b7 [2] 42 bb [2] 4e b1 [2] 59 ba [2] 42 f4 [2] 7f }

  condition:
    any of them
}