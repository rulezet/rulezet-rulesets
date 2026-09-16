rule TTP_XOR_MULT_DOSStub_c29b {
  strings:
    $key_c29b = { 96 f3 [2] e2 eb [2] a5 e9 [2] e2 f8 [2] ac f4 [2] a0 fe [2] b7 f5 [2] ac bb [2] 91 }

  condition:
    any of them
}