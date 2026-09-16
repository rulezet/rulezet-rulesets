rule TTP_XOR_MULT_DOSStub_c09b {
  strings:
    $key_c09b = { 94 f3 [2] e0 eb [2] a7 e9 [2] e0 f8 [2] ae f4 [2] a2 fe [2] b5 f5 [2] ae bb [2] 93 }

  condition:
    any of them
}