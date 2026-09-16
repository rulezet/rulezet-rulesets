rule TTP_XOR_MULT_DOSStub_782a {
  strings:
    $key_782a = { 2c 42 [2] 58 5a [2] 1f 58 [2] 58 49 [2] 16 45 [2] 1a 4f [2] 0d 44 [2] 16 0a [2] 2b }

  condition:
    any of them
}