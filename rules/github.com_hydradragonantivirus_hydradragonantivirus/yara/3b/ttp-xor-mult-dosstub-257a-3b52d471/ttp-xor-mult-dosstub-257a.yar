rule TTP_XOR_MULT_DOSStub_257a {
  strings:
    $key_257a = { 71 12 [2] 05 0a [2] 42 08 [2] 05 19 [2] 4b 15 [2] 47 1f [2] 50 14 [2] 4b 5a [2] 76 }

  condition:
    any of them
}