rule TTP_XOR_MULT_DOSStub_fdc1 {
  strings:
    $key_fdc1 = { a9 a9 [2] dd b1 [2] 9a b3 [2] dd a2 [2] 93 ae [2] 9f a4 [2] 88 af [2] 93 e1 [2] ae }

  condition:
    any of them
}