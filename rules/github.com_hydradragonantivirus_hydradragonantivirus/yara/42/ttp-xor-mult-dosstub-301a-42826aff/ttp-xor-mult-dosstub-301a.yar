rule TTP_XOR_MULT_DOSStub_301a {
  strings:
    $key_301a = { 64 72 [2] 10 6a [2] 57 68 [2] 10 79 [2] 5e 75 [2] 52 7f [2] 45 74 [2] 5e 3a [2] 63 }

  condition:
    any of them
}