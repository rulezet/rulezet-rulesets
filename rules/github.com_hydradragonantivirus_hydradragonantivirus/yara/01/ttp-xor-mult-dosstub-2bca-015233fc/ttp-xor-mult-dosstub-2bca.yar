rule TTP_XOR_MULT_DOSStub_2bca {
  strings:
    $key_2bca = { 7f a2 [2] 0b ba [2] 4c b8 [2] 0b a9 [2] 45 a5 [2] 49 af [2] 5e a4 [2] 45 ea [2] 78 }

  condition:
    any of them
}