rule TTP_XOR_MULT_DOSStub_c095 {
  strings:
    $key_c095 = { 94 fd [2] e0 e5 [2] a7 e7 [2] e0 f6 [2] ae fa [2] a2 f0 [2] b5 fb [2] ae b5 [2] 93 }

  condition:
    any of them
}