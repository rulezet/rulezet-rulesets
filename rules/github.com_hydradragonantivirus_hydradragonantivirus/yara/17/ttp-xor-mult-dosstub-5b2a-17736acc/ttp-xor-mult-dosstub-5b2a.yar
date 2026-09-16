rule TTP_XOR_MULT_DOSStub_5b2a {
  strings:
    $key_5b2a = { 0f 42 [2] 7b 5a [2] 3c 58 [2] 7b 49 [2] 35 45 [2] 39 4f [2] 2e 44 [2] 35 0a [2] 08 }

  condition:
    any of them
}