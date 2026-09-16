rule TTP_XOR_MULT_DOSStub_e8d8 {
  strings:
    $key_e8d8 = { bc b0 [2] c8 a8 [2] 8f aa [2] c8 bb [2] 86 b7 [2] 8a bd [2] 9d b6 [2] 86 f8 [2] bb }

  condition:
    any of them
}