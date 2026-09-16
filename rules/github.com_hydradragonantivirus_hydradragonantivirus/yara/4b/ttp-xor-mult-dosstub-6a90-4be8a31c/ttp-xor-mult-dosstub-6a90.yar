rule TTP_XOR_MULT_DOSStub_6a90 {
  strings:
    $key_6a90 = { 3e f8 [2] 4a e0 [2] 0d e2 [2] 4a f3 [2] 04 ff [2] 08 f5 [2] 1f fe [2] 04 b0 [2] 39 }

  condition:
    any of them
}