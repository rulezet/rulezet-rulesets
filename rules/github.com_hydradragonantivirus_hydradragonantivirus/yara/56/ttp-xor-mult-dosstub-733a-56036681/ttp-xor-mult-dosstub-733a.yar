rule TTP_XOR_MULT_DOSStub_733a {
  strings:
    $key_733a = { 27 52 [2] 53 4a [2] 14 48 [2] 53 59 [2] 1d 55 [2] 11 5f [2] 06 54 [2] 1d 1a [2] 20 }

  condition:
    any of them
}