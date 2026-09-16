rule TTP_XOR_MULT_DOSStub_69d8 {
  strings:
    $key_69d8 = { 3d b0 [2] 49 a8 [2] 0e aa [2] 49 bb [2] 07 b7 [2] 0b bd [2] 1c b6 [2] 07 f8 [2] 3a }

  condition:
    any of them
}