rule TTP_XOR_MULT_DOSStub_516a {
  strings:
    $key_516a = { 05 02 [2] 71 1a [2] 36 18 [2] 71 09 [2] 3f 05 [2] 33 0f [2] 24 04 [2] 3f 4a [2] 02 }

  condition:
    any of them
}