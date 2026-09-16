rule TTP_XOR_MULT_DOSStub_b220 {
  strings:
    $key_b220 = { e6 48 [2] 92 50 [2] d5 52 [2] 92 43 [2] dc 4f [2] d0 45 [2] c7 4e [2] dc 00 [2] e1 }

  condition:
    any of them
}