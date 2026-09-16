rule TTP_XOR_MULT_DOSStub_2a5a {
  strings:
    $key_2a5a = { 7e 32 [2] 0a 2a [2] 4d 28 [2] 0a 39 [2] 44 35 [2] 48 3f [2] 5f 34 [2] 44 7a [2] 79 }

  condition:
    any of them
}