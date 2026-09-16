rule TTP_XOR_MULT_DOSStub_141a {
  strings:
    $key_141a = { 40 72 [2] 34 6a [2] 73 68 [2] 34 79 [2] 7a 75 [2] 76 7f [2] 61 74 [2] 7a 3a [2] 47 }

  condition:
    any of them
}