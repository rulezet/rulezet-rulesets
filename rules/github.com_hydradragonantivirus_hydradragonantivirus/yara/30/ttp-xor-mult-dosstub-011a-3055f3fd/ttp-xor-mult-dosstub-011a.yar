rule TTP_XOR_MULT_DOSStub_011a {
  strings:
    $key_011a = { 55 72 [2] 21 6a [2] 66 68 [2] 21 79 [2] 6f 75 [2] 63 7f [2] 74 74 [2] 6f 3a [2] 52 }

  condition:
    any of them
}