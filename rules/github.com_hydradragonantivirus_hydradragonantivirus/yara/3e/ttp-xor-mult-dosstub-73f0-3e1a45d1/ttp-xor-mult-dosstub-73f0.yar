rule TTP_XOR_MULT_DOSStub_73f0 {
  strings:
    $key_73f0 = { 27 98 [2] 53 80 [2] 14 82 [2] 53 93 [2] 1d 9f [2] 11 95 [2] 06 9e [2] 1d d0 [2] 20 }

  condition:
    any of them
}