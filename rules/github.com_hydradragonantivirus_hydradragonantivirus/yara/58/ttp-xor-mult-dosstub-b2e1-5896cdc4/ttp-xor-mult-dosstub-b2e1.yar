rule TTP_XOR_MULT_DOSStub_b2e1 {
  strings:
    $key_b2e1 = { e6 89 [2] 92 91 [2] d5 93 [2] 92 82 [2] dc 8e [2] d0 84 [2] c7 8f [2] dc c1 [2] e1 }

  condition:
    any of them
}