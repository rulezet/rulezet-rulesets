rule TTP_XOR_MULT_DOSStub_b289 {
  strings:
    $key_b289 = { e6 e1 [2] 92 f9 [2] d5 fb [2] 92 ea [2] dc e6 [2] d0 ec [2] c7 e7 [2] dc a9 [2] e1 }

  condition:
    any of them
}