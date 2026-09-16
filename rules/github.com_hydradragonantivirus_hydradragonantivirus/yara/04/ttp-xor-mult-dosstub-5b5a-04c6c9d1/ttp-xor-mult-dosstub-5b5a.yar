rule TTP_XOR_MULT_DOSStub_5b5a {
  strings:
    $key_5b5a = { 0f 32 [2] 7b 2a [2] 3c 28 [2] 7b 39 [2] 35 35 [2] 39 3f [2] 2e 34 [2] 35 7a [2] 08 }

  condition:
    any of them
}