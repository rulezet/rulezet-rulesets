rule TTP_XOR_MULT_DOSStub_3bcb {
  strings:
    $key_3bcb = { 6f a3 [2] 1b bb [2] 5c b9 [2] 1b a8 [2] 55 a4 [2] 59 ae [2] 4e a5 [2] 55 eb [2] 68 }

  condition:
    any of them
}