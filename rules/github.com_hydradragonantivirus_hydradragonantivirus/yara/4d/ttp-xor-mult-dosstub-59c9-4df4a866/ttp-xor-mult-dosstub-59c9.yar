rule TTP_XOR_MULT_DOSStub_59c9 {
  strings:
    $key_59c9 = { 0d a1 [2] 79 b9 [2] 3e bb [2] 79 aa [2] 37 a6 [2] 3b ac [2] 2c a7 [2] 37 e9 [2] 0a }

  condition:
    any of them
}