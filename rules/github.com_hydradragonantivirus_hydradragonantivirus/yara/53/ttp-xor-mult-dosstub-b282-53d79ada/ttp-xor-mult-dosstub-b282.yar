rule TTP_XOR_MULT_DOSStub_b282 {
  strings:
    $key_b282 = { e6 ea [2] 92 f2 [2] d5 f0 [2] 92 e1 [2] dc ed [2] d0 e7 [2] c7 ec [2] dc a2 [2] e1 }

  condition:
    any of them
}