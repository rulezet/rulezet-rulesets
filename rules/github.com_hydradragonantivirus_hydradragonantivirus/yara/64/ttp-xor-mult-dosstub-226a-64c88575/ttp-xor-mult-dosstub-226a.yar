rule TTP_XOR_MULT_DOSStub_226a {
  strings:
    $key_226a = { 76 02 [2] 02 1a [2] 45 18 [2] 02 09 [2] 4c 05 [2] 40 0f [2] 57 04 [2] 4c 4a [2] 71 }

  condition:
    any of them
}