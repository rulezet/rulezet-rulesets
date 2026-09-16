rule TTP_XOR_MULT_DOSStub_6a96 {
  strings:
    $key_6a96 = { 3e fe [2] 4a e6 [2] 0d e4 [2] 4a f5 [2] 04 f9 [2] 08 f3 [2] 1f f8 [2] 04 b6 [2] 39 }

  condition:
    any of them
}