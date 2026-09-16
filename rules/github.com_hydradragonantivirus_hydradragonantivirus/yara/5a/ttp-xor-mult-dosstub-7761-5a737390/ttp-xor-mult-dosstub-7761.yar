rule TTP_XOR_MULT_DOSStub_7761 {
  strings:
    $key_7761 = { 23 09 [2] 57 11 [2] 10 13 [2] 57 02 [2] 19 0e [2] 15 04 [2] 02 0f [2] 19 41 [2] 24 }

  condition:
    any of them
}