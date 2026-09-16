rule TTP_XOR_MULT_DOSStub_115a {
  strings:
    $key_115a = { 45 32 [2] 31 2a [2] 76 28 [2] 31 39 [2] 7f 35 [2] 73 3f [2] 64 34 [2] 7f 7a [2] 42 }

  condition:
    any of them
}