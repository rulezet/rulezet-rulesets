rule TTP_XOR_MULT_DOSStub_4d54 {
  strings:
    $key_4d54 = { 19 3c [2] 6d 24 [2] 2a 26 [2] 6d 37 [2] 23 3b [2] 2f 31 [2] 38 3a [2] 23 74 [2] 1e }

  condition:
    any of them
}