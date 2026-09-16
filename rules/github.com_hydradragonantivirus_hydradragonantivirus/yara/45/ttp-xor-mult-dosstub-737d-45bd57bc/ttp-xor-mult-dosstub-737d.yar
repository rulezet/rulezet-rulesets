rule TTP_XOR_MULT_DOSStub_737d {
  strings:
    $key_737d = { 27 15 [2] 53 0d [2] 14 0f [2] 53 1e [2] 1d 12 [2] 11 18 [2] 06 13 [2] 1d 5d [2] 20 }

  condition:
    any of them
}