rule TTP_XOR_MULT_DOSStub_69d3 {
  strings:
    $key_69d3 = { 3d bb [2] 49 a3 [2] 0e a1 [2] 49 b0 [2] 07 bc [2] 0b b6 [2] 1c bd [2] 07 f3 [2] 3a }

  condition:
    any of them
}