rule TTP_XOR_MULT_DOSStub_c282 {
  strings:
    $key_c282 = { 96 ea [2] e2 f2 [2] a5 f0 [2] e2 e1 [2] ac ed [2] a0 e7 [2] b7 ec [2] ac a2 [2] 91 }

  condition:
    any of them
}