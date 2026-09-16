rule TTP_XOR_MULT_DOSStub_3d93 {
  strings:
    $key_3d93 = { 69 fb [2] 1d e3 [2] 5a e1 [2] 1d f0 [2] 53 fc [2] 5f f6 [2] 48 fd [2] 53 b3 [2] 6e }

  condition:
    any of them
}