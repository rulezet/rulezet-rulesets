rule TTP_XOR_MULT_DOSStub_251a {
  strings:
    $key_251a = { 71 72 [2] 05 6a [2] 42 68 [2] 05 79 [2] 4b 75 [2] 47 7f [2] 50 74 [2] 4b 3a [2] 76 }

  condition:
    any of them
}