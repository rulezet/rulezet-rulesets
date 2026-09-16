rule TTP_XOR_MULT_DOSStub_2bcb {
  strings:
    $key_2bcb = { 7f a3 [2] 0b bb [2] 4c b9 [2] 0b a8 [2] 45 a4 [2] 49 ae [2] 5e a5 [2] 45 eb [2] 78 }

  condition:
    any of them
}