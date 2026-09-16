rule TTP_XOR_MULT_DOSStub_455a {
  strings:
    $key_455a = { 11 32 [2] 65 2a [2] 22 28 [2] 65 39 [2] 2b 35 [2] 27 3f [2] 30 34 [2] 2b 7a [2] 16 }

  condition:
    any of them
}