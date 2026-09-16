rule TTP_XOR_MULT_DOSStub_b2e0 {
  strings:
    $key_b2e0 = { e6 88 [2] 92 90 [2] d5 92 [2] 92 83 [2] dc 8f [2] d0 85 [2] c7 8e [2] dc c0 [2] e1 }

  condition:
    any of them
}