rule TTP_XOR_MULT_DOSStub_b230 {
  strings:
    $key_b230 = { e6 58 [2] 92 40 [2] d5 42 [2] 92 53 [2] dc 5f [2] d0 55 [2] c7 5e [2] dc 10 [2] e1 }

  condition:
    any of them
}