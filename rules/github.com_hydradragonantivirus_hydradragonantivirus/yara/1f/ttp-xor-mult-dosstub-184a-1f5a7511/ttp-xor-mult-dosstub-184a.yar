rule TTP_XOR_MULT_DOSStub_184a {
  strings:
    $key_184a = { 4c 22 [2] 38 3a [2] 7f 38 [2] 38 29 [2] 76 25 [2] 7a 2f [2] 6d 24 [2] 76 6a [2] 4b }

  condition:
    any of them
}