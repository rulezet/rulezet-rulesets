rule TTP_XOR_MULT_DOSStub_b236 {
  strings:
    $key_b236 = { e6 5e [2] 92 46 [2] d5 44 [2] 92 55 [2] dc 59 [2] d0 53 [2] c7 58 [2] dc 16 [2] e1 }

  condition:
    any of them
}