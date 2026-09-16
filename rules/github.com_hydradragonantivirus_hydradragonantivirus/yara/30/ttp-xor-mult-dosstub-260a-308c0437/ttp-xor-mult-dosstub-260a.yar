rule TTP_XOR_MULT_DOSStub_260a {
  strings:
    $key_260a = { 72 62 [2] 06 7a [2] 41 78 [2] 06 69 [2] 48 65 [2] 44 6f [2] 53 64 [2] 48 2a [2] 75 }

  condition:
    any of them
}