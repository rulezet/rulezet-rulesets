rule TTP_XOR_MULT_DOSStub_e4d8 {
  strings:
    $key_e4d8 = { b0 b0 [2] c4 a8 [2] 83 aa [2] c4 bb [2] 8a b7 [2] 86 bd [2] 91 b6 [2] 8a f8 [2] b7 }

  condition:
    any of them
}