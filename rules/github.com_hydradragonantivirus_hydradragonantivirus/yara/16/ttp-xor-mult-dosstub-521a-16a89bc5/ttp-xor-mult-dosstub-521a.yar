rule TTP_XOR_MULT_DOSStub_521a {
  strings:
    $key_521a = { 06 72 [2] 72 6a [2] 35 68 [2] 72 79 [2] 3c 75 [2] 30 7f [2] 27 74 [2] 3c 3a [2] 01 }

  condition:
    any of them
}