rule TTP_XOR_MULT_DOSStub_4a78 {
  strings:
    $key_4a78 = { 1e 10 [2] 6a 08 [2] 2d 0a [2] 6a 1b [2] 24 17 [2] 28 1d [2] 3f 16 [2] 24 58 [2] 19 }

  condition:
    any of them
}