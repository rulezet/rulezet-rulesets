rule TTP_XOR_MULT_DOSStub_b06a {
  strings:
    $key_b06a = { e4 02 [2] 90 1a [2] d7 18 [2] 90 09 [2] de 05 [2] d2 0f [2] c5 04 [2] de 4a [2] e3 }

  condition:
    any of them
}