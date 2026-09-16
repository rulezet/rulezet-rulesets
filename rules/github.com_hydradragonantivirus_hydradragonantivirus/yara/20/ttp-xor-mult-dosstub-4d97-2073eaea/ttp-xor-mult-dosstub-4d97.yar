rule TTP_XOR_MULT_DOSStub_4d97 {
  strings:
    $key_4d97 = { 19 ff [2] 6d e7 [2] 2a e5 [2] 6d f4 [2] 23 f8 [2] 2f f2 [2] 38 f9 [2] 23 b7 [2] 1e }

  condition:
    any of them
}