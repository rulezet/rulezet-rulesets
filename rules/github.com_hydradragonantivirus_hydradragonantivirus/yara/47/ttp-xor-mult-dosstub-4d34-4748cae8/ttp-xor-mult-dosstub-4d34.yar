rule TTP_XOR_MULT_DOSStub_4d34 {
  strings:
    $key_4d34 = { 19 5c [2] 6d 44 [2] 2a 46 [2] 6d 57 [2] 23 5b [2] 2f 51 [2] 38 5a [2] 23 14 [2] 1e }

  condition:
    any of them
}