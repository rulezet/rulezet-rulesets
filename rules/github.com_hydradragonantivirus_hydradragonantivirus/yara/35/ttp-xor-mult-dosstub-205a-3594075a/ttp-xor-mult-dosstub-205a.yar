rule TTP_XOR_MULT_DOSStub_205a {
  strings:
    $key_205a = { 74 32 [2] 00 2a [2] 47 28 [2] 00 39 [2] 4e 35 [2] 42 3f [2] 55 34 [2] 4e 7a [2] 73 }

  condition:
    any of them
}