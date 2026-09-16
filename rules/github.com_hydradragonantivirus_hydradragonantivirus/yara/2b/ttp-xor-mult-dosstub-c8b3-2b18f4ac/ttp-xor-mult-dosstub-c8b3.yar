rule TTP_XOR_MULT_DOSStub_c8b3 {
  strings:
    $key_c8b3 = { 9c db [2] e8 c3 [2] af c1 [2] e8 d0 [2] a6 dc [2] aa d6 [2] bd dd [2] a6 93 [2] 9b }

  condition:
    any of them
}