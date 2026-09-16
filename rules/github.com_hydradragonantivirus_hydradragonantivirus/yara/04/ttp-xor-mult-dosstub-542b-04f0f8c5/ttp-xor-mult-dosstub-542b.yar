rule TTP_XOR_MULT_DOSStub_542b {
  strings:
    $key_542b = { 00 43 [2] 74 5b [2] 33 59 [2] 74 48 [2] 3a 44 [2] 36 4e [2] 21 45 [2] 3a 0b [2] 07 }

  condition:
    any of them
}