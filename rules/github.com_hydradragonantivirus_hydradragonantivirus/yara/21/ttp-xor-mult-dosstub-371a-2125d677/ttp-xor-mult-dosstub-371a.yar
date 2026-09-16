rule TTP_XOR_MULT_DOSStub_371a {
  strings:
    $key_371a = { 63 72 [2] 17 6a [2] 50 68 [2] 17 79 [2] 59 75 [2] 55 7f [2] 42 74 [2] 59 3a [2] 64 }

  condition:
    any of them
}