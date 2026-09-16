rule TTP_XOR_MULT_DOSStub_4dc9 {
  strings:
    $key_4dc9 = { 19 a1 [2] 6d b9 [2] 2a bb [2] 6d aa [2] 23 a6 [2] 2f ac [2] 38 a7 [2] 23 e9 [2] 1e }

  condition:
    any of them
}