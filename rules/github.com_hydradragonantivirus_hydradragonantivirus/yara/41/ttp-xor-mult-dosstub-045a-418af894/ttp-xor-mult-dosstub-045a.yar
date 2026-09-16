rule TTP_XOR_MULT_DOSStub_045a {
  strings:
    $key_045a = { 50 32 [2] 24 2a [2] 63 28 [2] 24 39 [2] 6a 35 [2] 66 3f [2] 71 34 [2] 6a 7a [2] 57 }

  condition:
    any of them
}