rule TTP_XOR_MULT_DOSStub_4df8 {
  strings:
    $key_4df8 = { 19 90 [2] 6d 88 [2] 2a 8a [2] 6d 9b [2] 23 97 [2] 2f 9d [2] 38 96 [2] 23 d8 [2] 1e }

  condition:
    any of them
}