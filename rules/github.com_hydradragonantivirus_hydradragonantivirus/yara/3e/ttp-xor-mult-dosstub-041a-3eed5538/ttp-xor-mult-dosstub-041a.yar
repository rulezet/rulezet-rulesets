rule TTP_XOR_MULT_DOSStub_041a {
  strings:
    $key_041a = { 50 72 [2] 24 6a [2] 63 68 [2] 24 79 [2] 6a 75 [2] 66 7f [2] 71 74 [2] 6a 3a [2] 57 }

  condition:
    any of them
}