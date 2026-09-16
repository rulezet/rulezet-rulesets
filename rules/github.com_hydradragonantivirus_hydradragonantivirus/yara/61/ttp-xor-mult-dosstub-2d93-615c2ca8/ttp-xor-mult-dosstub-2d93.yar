rule TTP_XOR_MULT_DOSStub_2d93 {
  strings:
    $key_2d93 = { 79 fb [2] 0d e3 [2] 4a e1 [2] 0d f0 [2] 43 fc [2] 4f f6 [2] 58 fd [2] 43 b3 [2] 7e }

  condition:
    any of them
}