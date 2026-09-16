rule TTP_XOR_MULT_DOSStub_7bcb {
  strings:
    $key_7bcb = { 2f a3 [2] 5b bb [2] 1c b9 [2] 5b a8 [2] 15 a4 [2] 19 ae [2] 0e a5 [2] 15 eb [2] 28 }

  condition:
    any of them
}