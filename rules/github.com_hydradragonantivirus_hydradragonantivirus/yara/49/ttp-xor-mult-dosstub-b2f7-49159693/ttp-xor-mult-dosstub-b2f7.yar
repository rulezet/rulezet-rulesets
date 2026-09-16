rule TTP_XOR_MULT_DOSStub_b2f7 {
  strings:
    $key_b2f7 = { e6 9f [2] 92 87 [2] d5 85 [2] 92 94 [2] dc 98 [2] d0 92 [2] c7 99 [2] dc d7 [2] e1 }

  condition:
    any of them
}