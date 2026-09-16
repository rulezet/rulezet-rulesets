rule TTP_XOR_MULT_DOSStub_5d97 {
  strings:
    $key_5d97 = { 09 ff [2] 7d e7 [2] 3a e5 [2] 7d f4 [2] 33 f8 [2] 3f f2 [2] 28 f9 [2] 33 b7 [2] 0e }

  condition:
    any of them
}