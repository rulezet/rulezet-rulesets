rule TTP_XOR_MULT_DOSStub_403a {
  strings:
    $key_403a = { 14 52 [2] 60 4a [2] 27 48 [2] 60 59 [2] 2e 55 [2] 22 5f [2] 35 54 [2] 2e 1a [2] 13 }

  condition:
    any of them
}