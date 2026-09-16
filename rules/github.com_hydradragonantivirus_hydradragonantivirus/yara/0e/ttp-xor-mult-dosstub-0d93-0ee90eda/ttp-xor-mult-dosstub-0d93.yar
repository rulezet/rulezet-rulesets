rule TTP_XOR_MULT_DOSStub_0d93 {
  strings:
    $key_0d93 = { 59 fb [2] 2d e3 [2] 6a e1 [2] 2d f0 [2] 63 fc [2] 6f f6 [2] 78 fd [2] 63 b3 [2] 5e }

  condition:
    any of them
}