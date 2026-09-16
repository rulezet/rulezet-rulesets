rule TTP_XOR_MULT_DOSStub_3d92 {
  strings:
    $key_3d92 = { 69 fa [2] 1d e2 [2] 5a e0 [2] 1d f1 [2] 53 fd [2] 5f f7 [2] 48 fc [2] 53 b2 [2] 6e }

  condition:
    any of them
}