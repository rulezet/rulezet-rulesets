rule TTP_XOR_MULT_DOSStub_146a {
  strings:
    $key_146a = { 40 02 [2] 34 1a [2] 73 18 [2] 34 09 [2] 7a 05 [2] 76 0f [2] 61 04 [2] 7a 4a [2] 47 }

  condition:
    any of them
}