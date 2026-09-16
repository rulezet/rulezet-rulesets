rule TTP_XOR_MULT_DOSStub_7d08 {
  strings:
    $key_7d08 = { 29 60 [2] 5d 78 [2] 1a 7a [2] 5d 6b [2] 13 67 [2] 1f 6d [2] 08 66 [2] 13 28 [2] 2e }

  condition:
    any of them
}