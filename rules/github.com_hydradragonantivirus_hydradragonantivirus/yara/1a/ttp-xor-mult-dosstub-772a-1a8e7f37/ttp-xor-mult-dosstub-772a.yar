rule TTP_XOR_MULT_DOSStub_772a {
  strings:
    $key_772a = { 23 42 [2] 57 5a [2] 10 58 [2] 57 49 [2] 19 45 [2] 15 4f [2] 02 44 [2] 19 0a [2] 24 }

  condition:
    any of them
}