rule TTP_XOR_MULT_DOSStub_7a2a {
  strings:
    $key_7a2a = { 2e 42 [2] 5a 5a [2] 1d 58 [2] 5a 49 [2] 14 45 [2] 18 4f [2] 0f 44 [2] 14 0a [2] 29 }

  condition:
    any of them
}