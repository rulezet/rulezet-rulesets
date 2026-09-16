rule TTP_XOR_MULT_DOSStub_fdc4 {
  strings:
    $key_fdc4 = { a9 ac [2] dd b4 [2] 9a b6 [2] dd a7 [2] 93 ab [2] 9f a1 [2] 88 aa [2] 93 e4 [2] ae }

  condition:
    any of them
}