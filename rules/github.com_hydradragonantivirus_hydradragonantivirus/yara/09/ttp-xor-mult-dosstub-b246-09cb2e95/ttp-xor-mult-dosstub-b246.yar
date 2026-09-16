rule TTP_XOR_MULT_DOSStub_b246 {
  strings:
    $key_b246 = { e6 2e [2] 92 36 [2] d5 34 [2] 92 25 [2] dc 29 [2] d0 23 [2] c7 28 [2] dc 66 [2] e1 }

  condition:
    any of them
}