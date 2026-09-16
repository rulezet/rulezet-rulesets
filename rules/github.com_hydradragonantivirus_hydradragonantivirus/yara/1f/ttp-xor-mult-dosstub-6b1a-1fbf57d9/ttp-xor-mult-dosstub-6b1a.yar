rule TTP_XOR_MULT_DOSStub_6b1a {
  strings:
    $key_6b1a = { 3f 72 [2] 4b 6a [2] 0c 68 [2] 4b 79 [2] 05 75 [2] 09 7f [2] 1e 74 [2] 05 3a [2] 38 }

  condition:
    any of them
}