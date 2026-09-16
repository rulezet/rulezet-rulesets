rule TTP_XOR_MULT_DOSStub_705a {
  strings:
    $key_705a = { 24 32 [2] 50 2a [2] 17 28 [2] 50 39 [2] 1e 35 [2] 12 3f [2] 05 34 [2] 1e 7a [2] 23 }

  condition:
    any of them
}