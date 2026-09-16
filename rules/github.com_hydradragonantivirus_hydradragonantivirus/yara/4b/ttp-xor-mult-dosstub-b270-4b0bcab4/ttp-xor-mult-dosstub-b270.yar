rule TTP_XOR_MULT_DOSStub_b270 {
  strings:
    $key_b270 = { e6 18 [2] 92 00 [2] d5 02 [2] 92 13 [2] dc 1f [2] d0 15 [2] c7 1e [2] dc 50 [2] e1 }

  condition:
    any of them
}