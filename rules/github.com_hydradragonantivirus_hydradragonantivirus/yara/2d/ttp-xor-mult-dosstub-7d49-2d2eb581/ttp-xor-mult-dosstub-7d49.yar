rule TTP_XOR_MULT_DOSStub_7d49 {
  strings:
    $key_7d49 = { 29 21 [2] 5d 39 [2] 1a 3b [2] 5d 2a [2] 13 26 [2] 1f 2c [2] 08 27 [2] 13 69 [2] 2e }

  condition:
    any of them
}