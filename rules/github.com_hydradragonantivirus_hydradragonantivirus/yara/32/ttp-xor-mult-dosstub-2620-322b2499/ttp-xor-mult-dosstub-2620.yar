rule TTP_XOR_MULT_DOSStub_2620 {
  strings:
    $key_2620 = { 72 48 [2] 06 50 [2] 41 52 [2] 06 43 [2] 48 4f [2] 44 45 [2] 53 4e [2] 48 00 [2] 75 }

  condition:
    any of them
}