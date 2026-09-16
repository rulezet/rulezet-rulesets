rule TTP_XOR_MULT_DOSStub_5d93 {
  strings:
    $key_5d93 = { 09 fb [2] 7d e3 [2] 3a e1 [2] 7d f0 [2] 33 fc [2] 3f f6 [2] 28 fd [2] 33 b3 [2] 0e }

  condition:
    any of them
}