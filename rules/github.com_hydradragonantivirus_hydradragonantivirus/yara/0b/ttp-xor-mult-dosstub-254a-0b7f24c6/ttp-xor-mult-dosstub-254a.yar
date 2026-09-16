rule TTP_XOR_MULT_DOSStub_254a {
  strings:
    $key_254a = { 71 22 [2] 05 3a [2] 42 38 [2] 05 29 [2] 4b 25 [2] 47 2f [2] 50 24 [2] 4b 6a [2] 76 }

  condition:
    any of them
}