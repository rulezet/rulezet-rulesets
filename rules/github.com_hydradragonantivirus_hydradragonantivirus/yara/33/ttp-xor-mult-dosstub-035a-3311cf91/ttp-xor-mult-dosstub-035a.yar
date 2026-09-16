rule TTP_XOR_MULT_DOSStub_035a {
  strings:
    $key_035a = { 57 32 [2] 23 2a [2] 64 28 [2] 23 39 [2] 6d 35 [2] 61 3f [2] 76 34 [2] 6d 7a [2] 50 }

  condition:
    any of them
}