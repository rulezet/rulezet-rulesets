rule TTP_XOR_MULT_DOSStub_352a {
  strings:
    $key_352a = { 61 42 [2] 15 5a [2] 52 58 [2] 15 49 [2] 5b 45 [2] 57 4f [2] 40 44 [2] 5b 0a [2] 66 }

  condition:
    any of them
}