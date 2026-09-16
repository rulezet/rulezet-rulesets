rule TTP_XOR_MULT_DOSStub_f0d8 {
  strings:
    $key_f0d8 = { a4 b0 [2] d0 a8 [2] 97 aa [2] d0 bb [2] 9e b7 [2] 92 bd [2] 85 b6 [2] 9e f8 [2] a3 }

  condition:
    any of them
}