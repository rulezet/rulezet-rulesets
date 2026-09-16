rule TTP_XOR_MULT_DOSStub_183a {
  strings:
    $key_183a = { 4c 52 [2] 38 4a [2] 7f 48 [2] 38 59 [2] 76 55 [2] 7a 5f [2] 6d 54 [2] 76 1a [2] 4b }

  condition:
    any of them
}