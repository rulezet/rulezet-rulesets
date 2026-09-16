rule TTP_XOR_MULT_DOSStub_547f {
  strings:
    $key_547f = { 00 17 [2] 74 0f [2] 33 0d [2] 74 1c [2] 3a 10 [2] 36 1a [2] 21 11 [2] 3a 5f [2] 07 }

  condition:
    any of them
}