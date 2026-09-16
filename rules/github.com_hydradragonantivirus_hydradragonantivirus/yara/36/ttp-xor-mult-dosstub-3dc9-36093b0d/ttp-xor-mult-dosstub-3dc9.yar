rule TTP_XOR_MULT_DOSStub_3dc9 {
  strings:
    $key_3dc9 = { 69 a1 [2] 1d b9 [2] 5a bb [2] 1d aa [2] 53 a6 [2] 5f ac [2] 48 a7 [2] 53 e9 [2] 6e }

  condition:
    any of them
}