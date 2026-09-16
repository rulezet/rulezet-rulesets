rule TTP_XOR_MULT_DOSStub_4d39 {
  strings:
    $key_4d39 = { 19 51 [2] 6d 49 [2] 2a 4b [2] 6d 5a [2] 23 56 [2] 2f 5c [2] 38 57 [2] 23 19 [2] 1e }

  condition:
    any of them
}