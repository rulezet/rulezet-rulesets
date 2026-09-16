rule TTP_XOR_MULT_DOSStub_655a {
  strings:
    $key_655a = { 31 32 [2] 45 2a [2] 02 28 [2] 45 39 [2] 0b 35 [2] 07 3f [2] 10 34 [2] 0b 7a [2] 36 }

  condition:
    any of them
}