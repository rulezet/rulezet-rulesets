rule TTP_XOR_MULT_DOSStub_5dc9 {
  strings:
    $key_5dc9 = { 09 a1 [2] 7d b9 [2] 3a bb [2] 7d aa [2] 33 a6 [2] 3f ac [2] 28 a7 [2] 33 e9 [2] 0e }

  condition:
    any of them
}