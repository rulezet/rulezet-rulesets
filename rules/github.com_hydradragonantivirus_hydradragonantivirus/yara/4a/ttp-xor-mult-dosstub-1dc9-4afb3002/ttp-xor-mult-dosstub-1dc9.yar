rule TTP_XOR_MULT_DOSStub_1dc9 {
  strings:
    $key_1dc9 = { 49 a1 [2] 3d b9 [2] 7a bb [2] 3d aa [2] 73 a6 [2] 7f ac [2] 68 a7 [2] 73 e9 [2] 4e }

  condition:
    any of them
}