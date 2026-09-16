rule TTP_XOR_MULT_DOSStub_7dc9 {
  strings:
    $key_7dc9 = { 29 a1 [2] 5d b9 [2] 1a bb [2] 5d aa [2] 13 a6 [2] 1f ac [2] 08 a7 [2] 13 e9 [2] 2e }

  condition:
    any of them
}