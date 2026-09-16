rule TTP_XOR_MULT_DOSStub_0bd5 {
  strings:
    $key_0bd5 = { 5f bd [2] 2b a5 [2] 6c a7 [2] 2b b6 [2] 65 ba [2] 69 b0 [2] 7e bb [2] 65 f5 [2] 58 }

  condition:
    any of them
}