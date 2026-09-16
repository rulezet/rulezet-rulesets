rule TTP_XOR_MULT_DOSStub_79d3 {
  strings:
    $key_79d3 = { 2d bb [2] 59 a3 [2] 1e a1 [2] 59 b0 [2] 17 bc [2] 1b b6 [2] 0c bd [2] 17 f3 [2] 2a }

  condition:
    any of them
}