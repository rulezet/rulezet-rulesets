rule TTP_XOR_MULT_DOSStub_11d8 {
  strings:
    $key_11d8 = { 45 b0 [2] 31 a8 [2] 76 aa [2] 31 bb [2] 7f b7 [2] 73 bd [2] 64 b6 [2] 7f f8 [2] 42 }

  condition:
    any of them
}