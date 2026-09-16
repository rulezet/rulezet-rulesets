rule TTP_XOR_MULT_DOSStub_65d8 {
  strings:
    $key_65d8 = { 31 b0 [2] 45 a8 [2] 02 aa [2] 45 bb [2] 0b b7 [2] 07 bd [2] 10 b6 [2] 0b f8 [2] 36 }

  condition:
    any of them
}