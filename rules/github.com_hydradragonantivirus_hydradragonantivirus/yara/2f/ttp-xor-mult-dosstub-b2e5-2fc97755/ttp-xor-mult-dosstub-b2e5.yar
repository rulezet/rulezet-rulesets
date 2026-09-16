rule TTP_XOR_MULT_DOSStub_b2e5 {
  strings:
    $key_b2e5 = { e6 8d [2] 92 95 [2] d5 97 [2] 92 86 [2] dc 8a [2] d0 80 [2] c7 8b [2] dc c5 [2] e1 }

  condition:
    any of them
}