rule TTP_XOR_MULT_DOSStub_7b2a {
  strings:
    $key_7b2a = { 2f 42 [2] 5b 5a [2] 1c 58 [2] 5b 49 [2] 15 45 [2] 19 4f [2] 0e 44 [2] 15 0a [2] 28 }

  condition:
    any of them
}