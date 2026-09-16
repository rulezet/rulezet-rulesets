rule TTP_XOR_MULT_DOSStub_7d54 {
  strings:
    $key_7d54 = { 29 3c [2] 5d 24 [2] 1a 26 [2] 5d 37 [2] 13 3b [2] 1f 31 [2] 08 3a [2] 13 74 [2] 2e }

  condition:
    any of them
}