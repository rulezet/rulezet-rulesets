rule TTP_XOR_MULT_DOSStub_543b {
  strings:
    $key_543b = { 00 53 [2] 74 4b [2] 33 49 [2] 74 58 [2] 3a 54 [2] 36 5e [2] 21 55 [2] 3a 1b [2] 07 }

  condition:
    any of them
}