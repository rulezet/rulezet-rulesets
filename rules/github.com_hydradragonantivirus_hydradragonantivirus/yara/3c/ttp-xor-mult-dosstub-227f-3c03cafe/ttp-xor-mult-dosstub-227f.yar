rule TTP_XOR_MULT_DOSStub_227f {
  strings:
    $key_227f = { 76 17 [2] 02 0f [2] 45 0d [2] 02 1c [2] 4c 10 [2] 40 1a [2] 57 11 [2] 4c 5f [2] 71 }

  condition:
    any of them
}