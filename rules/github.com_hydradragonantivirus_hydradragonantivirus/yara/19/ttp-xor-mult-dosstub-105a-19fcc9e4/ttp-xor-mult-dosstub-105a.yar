rule TTP_XOR_MULT_DOSStub_105a {
  strings:
    $key_105a = { 44 32 [2] 30 2a [2] 77 28 [2] 30 39 [2] 7e 35 [2] 72 3f [2] 65 34 [2] 7e 7a [2] 43 }

  condition:
    any of them
}