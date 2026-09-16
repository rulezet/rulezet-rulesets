rule TTP_XOR_MULT_DOSStub_7d92 {
  strings:
    $key_7d92 = { 29 fa [2] 5d e2 [2] 1a e0 [2] 5d f1 [2] 13 fd [2] 1f f7 [2] 08 fc [2] 13 b2 [2] 2e }

  condition:
    any of them
}