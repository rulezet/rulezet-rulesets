rule TTP_XOR_MULT_DOSStub_71d8 {
  strings:
    $key_71d8 = { 25 b0 [2] 51 a8 [2] 16 aa [2] 51 bb [2] 1f b7 [2] 13 bd [2] 04 b6 [2] 1f f8 [2] 22 }

  condition:
    any of them
}