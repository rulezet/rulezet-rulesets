rule TTP_XOR_MULT_DOSStub_405a {
  strings:
    $key_405a = { 14 32 [2] 60 2a [2] 27 28 [2] 60 39 [2] 2e 35 [2] 22 3f [2] 35 34 [2] 2e 7a [2] 13 }

  condition:
    any of them
}