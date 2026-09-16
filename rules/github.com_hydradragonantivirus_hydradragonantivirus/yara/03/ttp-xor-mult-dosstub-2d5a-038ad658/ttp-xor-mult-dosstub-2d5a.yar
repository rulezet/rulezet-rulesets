rule TTP_XOR_MULT_DOSStub_2d5a {
  strings:
    $key_2d5a = { 79 32 [2] 0d 2a [2] 4a 28 [2] 0d 39 [2] 43 35 [2] 4f 3f [2] 58 34 [2] 43 7a [2] 7e }

  condition:
    any of them
}