rule TTP_XOR_MULT_DOSStub_7d97 {
  strings:
    $key_7d97 = { 29 ff [2] 5d e7 [2] 1a e5 [2] 5d f4 [2] 13 f8 [2] 1f f2 [2] 08 f9 [2] 13 b7 [2] 2e }

  condition:
    any of them
}