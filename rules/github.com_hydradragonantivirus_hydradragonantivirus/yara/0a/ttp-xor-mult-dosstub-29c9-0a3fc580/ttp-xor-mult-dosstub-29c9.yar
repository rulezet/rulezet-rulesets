rule TTP_XOR_MULT_DOSStub_29c9 {
  strings:
    $key_29c9 = { 7d a1 [2] 09 b9 [2] 4e bb [2] 09 aa [2] 47 a6 [2] 4b ac [2] 5c a7 [2] 47 e9 [2] 7a }

  condition:
    any of them
}