rule TTP_XOR_MULT_DOSStub_6d95 {
  strings:
    $key_6d95 = { 39 fd [2] 4d e5 [2] 0a e7 [2] 4d f6 [2] 03 fa [2] 0f f0 [2] 18 fb [2] 03 b5 [2] 3e }

  condition:
    any of them
}