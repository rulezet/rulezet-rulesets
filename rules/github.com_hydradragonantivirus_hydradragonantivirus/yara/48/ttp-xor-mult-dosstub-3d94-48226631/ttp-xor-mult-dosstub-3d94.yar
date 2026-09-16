rule TTP_XOR_MULT_DOSStub_3d94 {
  strings:
    $key_3d94 = { 69 fc [2] 1d e4 [2] 5a e6 [2] 1d f7 [2] 53 fb [2] 5f f1 [2] 48 fa [2] 53 b4 [2] 6e }

  condition:
    any of them
}