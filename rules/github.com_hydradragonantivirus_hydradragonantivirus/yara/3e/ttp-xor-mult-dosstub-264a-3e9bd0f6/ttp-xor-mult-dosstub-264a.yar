rule TTP_XOR_MULT_DOSStub_264a {
  strings:
    $key_264a = { 72 22 [2] 06 3a [2] 41 38 [2] 06 29 [2] 48 25 [2] 44 2f [2] 53 24 [2] 48 6a [2] 75 }

  condition:
    any of them
}