rule TTP_XOR_MULT_DOSStub_265a {
  strings:
    $key_265a = { 72 32 [2] 06 2a [2] 41 28 [2] 06 39 [2] 48 35 [2] 44 3f [2] 53 34 [2] 48 7a [2] 75 }

  condition:
    any of them
}