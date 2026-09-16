rule TTP_XOR_MULT_DOSStub_6bd5 {
  strings:
    $key_6bd5 = { 3f bd [2] 4b a5 [2] 0c a7 [2] 4b b6 [2] 05 ba [2] 09 b0 [2] 1e bb [2] 05 f5 [2] 38 }

  condition:
    any of them
}