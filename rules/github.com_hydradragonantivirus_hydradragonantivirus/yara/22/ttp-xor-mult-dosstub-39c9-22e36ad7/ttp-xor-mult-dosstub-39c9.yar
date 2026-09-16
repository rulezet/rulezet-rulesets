rule TTP_XOR_MULT_DOSStub_39c9 {
  strings:
    $key_39c9 = { 6d a1 [2] 19 b9 [2] 5e bb [2] 19 aa [2] 57 a6 [2] 5b ac [2] 4c a7 [2] 57 e9 [2] 6a }

  condition:
    any of them
}