rule TTP_XOR_MULT_DOSStub_7d44 {
  strings:
    $key_7d44 = { 29 2c [2] 5d 34 [2] 1a 36 [2] 5d 27 [2] 13 2b [2] 1f 21 [2] 08 2a [2] 13 64 [2] 2e }

  condition:
    any of them
}