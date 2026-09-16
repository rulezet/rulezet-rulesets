rule TTP_XOR_MULT_DOSStub_4df5 {
  strings:
    $key_4df5 = { 19 9d [2] 6d 85 [2] 2a 87 [2] 6d 96 [2] 23 9a [2] 2f 90 [2] 38 9b [2] 23 d5 [2] 1e }

  condition:
    any of them
}