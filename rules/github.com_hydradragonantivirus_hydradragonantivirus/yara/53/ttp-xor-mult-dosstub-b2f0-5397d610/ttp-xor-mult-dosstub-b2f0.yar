rule TTP_XOR_MULT_DOSStub_b2f0 {
  strings:
    $key_b2f0 = { e6 98 [2] 92 80 [2] d5 82 [2] 92 93 [2] dc 9f [2] d0 95 [2] c7 9e [2] dc d0 [2] e1 }

  condition:
    any of them
}