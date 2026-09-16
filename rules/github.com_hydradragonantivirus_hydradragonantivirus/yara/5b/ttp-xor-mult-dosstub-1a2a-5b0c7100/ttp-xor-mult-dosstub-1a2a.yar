rule TTP_XOR_MULT_DOSStub_1a2a {
  strings:
    $key_1a2a = { 4e 42 [2] 3a 5a [2] 7d 58 [2] 3a 49 [2] 74 45 [2] 78 4f [2] 6f 44 [2] 74 0a [2] 49 }

  condition:
    any of them
}