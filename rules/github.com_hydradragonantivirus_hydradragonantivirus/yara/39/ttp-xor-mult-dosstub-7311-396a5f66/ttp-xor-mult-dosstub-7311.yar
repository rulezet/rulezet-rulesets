rule TTP_XOR_MULT_DOSStub_7311 {
  strings:
    $key_7311 = { 27 79 [2] 53 61 [2] 14 63 [2] 53 72 [2] 1d 7e [2] 11 74 [2] 06 7f [2] 1d 31 [2] 20 }

  condition:
    any of them
}