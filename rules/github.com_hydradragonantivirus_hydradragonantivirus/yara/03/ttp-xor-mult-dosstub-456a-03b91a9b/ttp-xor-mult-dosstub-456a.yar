rule TTP_XOR_MULT_DOSStub_456a {
  strings:
    $key_456a = { 11 02 [2] 65 1a [2] 22 18 [2] 65 09 [2] 2b 05 [2] 27 0f [2] 30 04 [2] 2b 4a [2] 16 }

  condition:
    any of them
}