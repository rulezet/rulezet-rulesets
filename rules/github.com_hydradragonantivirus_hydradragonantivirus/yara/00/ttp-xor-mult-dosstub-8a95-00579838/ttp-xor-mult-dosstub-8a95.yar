rule TTP_XOR_MULT_DOSStub_8a95 {
  strings:
    $key_8a95 = { de fd [2] aa e5 [2] ed e7 [2] aa f6 [2] e4 fa [2] e8 f0 [2] ff fb [2] e4 b5 [2] d9 }

  condition:
    any of them
}