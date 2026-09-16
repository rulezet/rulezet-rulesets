rule TTP_XOR_MULT_DOSStub_c090 {
  strings:
    $key_c090 = { 94 f8 [2] e0 e0 [2] a7 e2 [2] e0 f3 [2] ae ff [2] a2 f5 [2] b5 fe [2] ae b0 [2] 93 }

  condition:
    any of them
}