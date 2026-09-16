rule TTP_XOR_MULT_DOSStub_0bcb {
  strings:
    $key_0bcb = { 5f a3 [2] 2b bb [2] 6c b9 [2] 2b a8 [2] 65 a4 [2] 69 ae [2] 7e a5 [2] 65 eb [2] 58 }

  condition:
    any of them
}