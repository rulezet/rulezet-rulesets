rule TTP_XOR_MULT_DOSStub_4d5a {
  strings:
    $key_4d5a = { 19 32 [2] 6d 2a [2] 2a 28 [2] 6d 39 [2] 23 35 [2] 2f 3f [2] 38 34 [2] 23 7a [2] 1e }

  condition:
    any of them
}