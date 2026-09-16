rule TTP_XOR_MULT_DOSStub_3a2a {
  strings:
    $key_3a2a = { 6e 42 [2] 1a 5a [2] 5d 58 [2] 1a 49 [2] 54 45 [2] 58 4f [2] 4f 44 [2] 54 0a [2] 69 }

  condition:
    any of them
}