rule TTP_XOR_MULT_DOSStub_49c9 {
  strings:
    $key_49c9 = { 1d a1 [2] 69 b9 [2] 2e bb [2] 69 aa [2] 27 a6 [2] 2b ac [2] 3c a7 [2] 27 e9 [2] 1a }

  condition:
    any of them
}