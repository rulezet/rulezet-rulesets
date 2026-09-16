rule TTP_XOR_MULT_DOSStub_4d62 {
  strings:
    $key_4d62 = { 19 0a [2] 6d 12 [2] 2a 10 [2] 6d 01 [2] 23 0d [2] 2f 07 [2] 38 0c [2] 23 42 [2] 1e }

  condition:
    any of them
}