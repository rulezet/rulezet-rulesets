rule TTP_XOR_MULT_DOSStub_c09a {
  strings:
    $key_c09a = { 94 f2 [2] e0 ea [2] a7 e8 [2] e0 f9 [2] ae f5 [2] a2 ff [2] b5 f4 [2] ae ba [2] 93 }

  condition:
    any of them
}