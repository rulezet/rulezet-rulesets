rule TTP_XOR_MULT_DOSStub_09c9 {
  strings:
    $key_09c9 = { 5d a1 [2] 29 b9 [2] 6e bb [2] 29 aa [2] 67 a6 [2] 6b ac [2] 7c a7 [2] 67 e9 [2] 5a }

  condition:
    any of them
}