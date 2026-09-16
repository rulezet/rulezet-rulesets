rule TTP_XOR_MULT_DOSStub_4d78 {
  strings:
    $key_4d78 = { 19 10 [2] 6d 08 [2] 2a 0a [2] 6d 1b [2] 23 17 [2] 2f 1d [2] 38 16 [2] 23 58 [2] 1e }

  condition:
    any of them
}