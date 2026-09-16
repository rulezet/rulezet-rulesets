rule TTP_XOR_MULT_DOSStub_4af0 {
  strings:
    $key_4af0 = { 1e 98 [2] 6a 80 [2] 2d 82 [2] 6a 93 [2] 24 9f [2] 28 95 [2] 3f 9e [2] 24 d0 [2] 19 }

  condition:
    any of them
}