rule TTP_XOR_MULT_DOSStub_255a {
  strings:
    $key_255a = { 71 32 [2] 05 2a [2] 42 28 [2] 05 39 [2] 4b 35 [2] 47 3f [2] 50 34 [2] 4b 7a [2] 76 }

  condition:
    any of them
}