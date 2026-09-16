rule TTP_XOR_MULT_DOSStub_b683 {
  strings:
    $key_b683 = { e2 eb [2] 96 f3 [2] d1 f1 [2] 96 e0 [2] d8 ec [2] d4 e6 [2] c3 ed [2] d8 a3 [2] e5 }

  condition:
    any of them
}