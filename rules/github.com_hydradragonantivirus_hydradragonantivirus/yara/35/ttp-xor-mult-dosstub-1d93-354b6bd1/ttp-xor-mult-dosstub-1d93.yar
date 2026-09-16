rule TTP_XOR_MULT_DOSStub_1d93 {
  strings:
    $key_1d93 = { 49 fb [2] 3d e3 [2] 7a e1 [2] 3d f0 [2] 73 fc [2] 7f f6 [2] 68 fd [2] 73 b3 [2] 4e }

  condition:
    any of them
}