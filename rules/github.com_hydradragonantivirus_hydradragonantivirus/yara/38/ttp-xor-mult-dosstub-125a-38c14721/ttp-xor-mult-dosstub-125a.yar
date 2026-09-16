rule TTP_XOR_MULT_DOSStub_125a {
  strings:
    $key_125a = { 46 32 [2] 32 2a [2] 75 28 [2] 32 39 [2] 7c 35 [2] 70 3f [2] 67 34 [2] 7c 7a [2] 41 }

  condition:
    any of them
}