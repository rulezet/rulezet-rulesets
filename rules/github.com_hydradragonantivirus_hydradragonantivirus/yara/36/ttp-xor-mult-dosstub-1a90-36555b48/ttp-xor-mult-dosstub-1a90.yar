rule TTP_XOR_MULT_DOSStub_1a90 {
  strings:
    $key_1a90 = { 4e f8 [2] 3a e0 [2] 7d e2 [2] 3a f3 [2] 74 ff [2] 78 f5 [2] 6f fe [2] 74 b0 [2] 49 }

  condition:
    any of them
}