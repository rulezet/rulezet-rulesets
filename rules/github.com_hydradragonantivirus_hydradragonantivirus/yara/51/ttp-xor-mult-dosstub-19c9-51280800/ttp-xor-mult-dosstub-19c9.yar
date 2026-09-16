rule TTP_XOR_MULT_DOSStub_19c9 {
  strings:
    $key_19c9 = { 4d a1 [2] 39 b9 [2] 7e bb [2] 39 aa [2] 77 a6 [2] 7b ac [2] 6c a7 [2] 77 e9 [2] 4a }

  condition:
    any of them
}