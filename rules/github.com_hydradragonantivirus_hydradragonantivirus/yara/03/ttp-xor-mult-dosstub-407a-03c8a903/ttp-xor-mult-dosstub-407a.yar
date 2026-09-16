rule TTP_XOR_MULT_DOSStub_407a {
  strings:
    $key_407a = { 14 12 [2] 60 0a [2] 27 08 [2] 60 19 [2] 2e 15 [2] 22 1f [2] 35 14 [2] 2e 5a [2] 13 }

  condition:
    any of them
}