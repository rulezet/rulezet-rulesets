rule TTP_XOR_MULT_DOSStub_61d8 {
  strings:
    $key_61d8 = { 35 b0 [2] 41 a8 [2] 06 aa [2] 41 bb [2] 0f b7 [2] 03 bd [2] 14 b6 [2] 0f f8 [2] 32 }

  condition:
    any of them
}