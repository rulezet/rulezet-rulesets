rule TTP_XOR_MULT_DOSStub_0b2a {
  strings:
    $key_0b2a = { 5f 42 [2] 2b 5a [2] 6c 58 [2] 2b 49 [2] 65 45 [2] 69 4f [2] 7e 44 [2] 65 0a [2] 58 }

  condition:
    any of them
}