rule TTP_XOR_MULT_DOSStub_465a {
  strings:
    $key_465a = { 12 32 [2] 66 2a [2] 21 28 [2] 66 39 [2] 28 35 [2] 24 3f [2] 33 34 [2] 28 7a [2] 15 }

  condition:
    any of them
}