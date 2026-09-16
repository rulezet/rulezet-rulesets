rule TTP_XOR_MULT_DOSStub_4d08 {
  strings:
    $key_4d08 = { 19 60 [2] 6d 78 [2] 2a 7a [2] 6d 6b [2] 23 67 [2] 2f 6d [2] 38 66 [2] 23 28 [2] 1e }

  condition:
    any of them
}