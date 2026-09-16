rule TTP_XOR_MULT_DOSStub_b2f1 {
  strings:
    $key_b2f1 = { e6 99 [2] 92 81 [2] d5 83 [2] 92 92 [2] dc 9e [2] d0 94 [2] c7 9f [2] dc d1 [2] e1 }

  condition:
    any of them
}