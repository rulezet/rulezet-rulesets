rule TTP_XOR_MULT_DOSStub_3b5a {
  strings:
    $key_3b5a = { 6f 32 [2] 1b 2a [2] 5c 28 [2] 1b 39 [2] 55 35 [2] 59 3f [2] 4e 34 [2] 55 7a [2] 68 }

  condition:
    any of them
}