rule TTP_XOR_MULT_DOSStub_635a {
  strings:
    $key_635a = { 37 32 [2] 43 2a [2] 04 28 [2] 43 39 [2] 0d 35 [2] 01 3f [2] 16 34 [2] 0d 7a [2] 30 }

  condition:
    any of them
}