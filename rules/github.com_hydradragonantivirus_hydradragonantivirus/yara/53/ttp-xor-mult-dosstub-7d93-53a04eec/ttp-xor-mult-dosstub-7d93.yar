rule TTP_XOR_MULT_DOSStub_7d93 {
  strings:
    $key_7d93 = { 29 fb [2] 5d e3 [2] 1a e1 [2] 5d f0 [2] 13 fc [2] 1f f6 [2] 08 fd [2] 13 b3 [2] 2e }

  condition:
    any of them
}