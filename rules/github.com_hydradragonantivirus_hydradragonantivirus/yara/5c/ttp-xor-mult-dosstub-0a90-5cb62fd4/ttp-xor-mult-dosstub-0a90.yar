rule TTP_XOR_MULT_DOSStub_0a90 {
  strings:
    $key_0a90 = { 5e f8 [2] 2a e0 [2] 6d e2 [2] 2a f3 [2] 64 ff [2] 68 f5 [2] 7f fe [2] 64 b0 [2] 59 }

  condition:
    any of them
}