rule TTP_XOR_MULT_DOSStub_5bcb {
  strings:
    $key_5bcb = { 0f a3 [2] 7b bb [2] 3c b9 [2] 7b a8 [2] 35 a4 [2] 39 ae [2] 2e a5 [2] 35 eb [2] 08 }

  condition:
    any of them
}