rule TTP_XOR_MULT_DOSStub_7d39 {
  strings:
    $key_7d39 = { 29 51 [2] 5d 49 [2] 1a 4b [2] 5d 5a [2] 13 56 [2] 1f 5c [2] 08 57 [2] 13 19 [2] 2e }

  condition:
    any of them
}