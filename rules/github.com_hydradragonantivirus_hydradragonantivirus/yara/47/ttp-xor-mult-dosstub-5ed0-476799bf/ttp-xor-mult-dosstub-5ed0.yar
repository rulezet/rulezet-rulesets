rule TTP_XOR_MULT_DOSStub_5ed0 {
  strings:
    $key_5ed0 = { 0a b8 [2] 7e a0 [2] 39 a2 [2] 7e b3 [2] 30 bf [2] 3c b5 [2] 2b be [2] 30 f0 [2] 0d }

  condition:
    any of them
}