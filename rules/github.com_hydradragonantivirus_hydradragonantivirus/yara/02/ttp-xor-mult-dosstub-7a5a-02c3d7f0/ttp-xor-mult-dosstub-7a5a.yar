rule TTP_XOR_MULT_DOSStub_7a5a {
  strings:
    $key_7a5a = { 2e 32 [2] 5a 2a [2] 1d 28 [2] 5a 39 [2] 14 35 [2] 18 3f [2] 0f 34 [2] 14 7a [2] 29 }

  condition:
    any of them
}