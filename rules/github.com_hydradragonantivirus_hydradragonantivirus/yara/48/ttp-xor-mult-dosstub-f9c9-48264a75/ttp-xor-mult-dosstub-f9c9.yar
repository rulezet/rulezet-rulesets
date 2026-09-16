rule TTP_XOR_MULT_DOSStub_f9c9 {
  strings:
    $key_f9c9 = { ad a1 [2] d9 b9 [2] 9e bb [2] d9 aa [2] 97 a6 [2] 9b ac [2] 8c a7 [2] 97 e9 [2] aa }

  condition:
    any of them
}