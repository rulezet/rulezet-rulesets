rule TTP_XOR_MULT_DOSStub_370a {
  strings:
    $key_370a = { 63 62 [2] 17 7a [2] 50 78 [2] 17 69 [2] 59 65 [2] 55 6f [2] 42 64 [2] 59 2a [2] 64 }

  condition:
    any of them
}