rule TTP_XOR_MULT_DOSStub_c09e {
  strings:
    $key_c09e = { 94 f6 [2] e0 ee [2] a7 ec [2] e0 fd [2] ae f1 [2] a2 fb [2] b5 f0 [2] ae be [2] 93 }

  condition:
    any of them
}