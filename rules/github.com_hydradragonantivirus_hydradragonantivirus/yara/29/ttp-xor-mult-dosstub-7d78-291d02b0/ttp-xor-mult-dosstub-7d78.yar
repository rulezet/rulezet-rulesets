rule TTP_XOR_MULT_DOSStub_7d78 {
  strings:
    $key_7d78 = { 29 10 [2] 5d 08 [2] 1a 0a [2] 5d 1b [2] 13 17 [2] 1f 1d [2] 08 16 [2] 13 58 [2] 2e }

  condition:
    any of them
}