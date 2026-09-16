rule TTP_XOR_MULT_DOSStub_2dc9 {
  strings:
    $key_2dc9 = { 79 a1 [2] 0d b9 [2] 4a bb [2] 0d aa [2] 43 a6 [2] 4f ac [2] 58 a7 [2] 43 e9 [2] 7e }

  condition:
    any of them
}