rule TTP_XOR_MULT_DOSStub_3c5a {
  strings:
    $key_3c5a = { 68 32 [2] 1c 2a [2] 5b 28 [2] 1c 39 [2] 52 35 [2] 5e 3f [2] 49 34 [2] 52 7a [2] 6f }

  condition:
    any of them
}