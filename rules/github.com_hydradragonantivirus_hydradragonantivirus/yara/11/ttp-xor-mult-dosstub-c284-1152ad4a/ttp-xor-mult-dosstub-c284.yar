rule TTP_XOR_MULT_DOSStub_c284 {
  strings:
    $key_c284 = { 96 ec [2] e2 f4 [2] a5 f6 [2] e2 e7 [2] ac eb [2] a0 e1 [2] b7 ea [2] ac a4 [2] 91 }

  condition:
    any of them
}