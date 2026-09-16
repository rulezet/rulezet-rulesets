rule TTP_XOR_MULT_DOSStub_305a {
  strings:
    $key_305a = { 64 32 [2] 10 2a [2] 57 28 [2] 10 39 [2] 5e 35 [2] 52 3f [2] 45 34 [2] 5e 7a [2] 63 }

  condition:
    any of them
}