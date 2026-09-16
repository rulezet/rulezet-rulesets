rule TTP_XOR_MULT_DOSStub_b226 {
  strings:
    $key_b226 = { e6 4e [2] 92 56 [2] d5 54 [2] 92 45 [2] dc 49 [2] d0 43 [2] c7 48 [2] dc 06 [2] e1 }

  condition:
    any of them
}