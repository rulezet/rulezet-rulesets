rule TTP_XOR_MULT_DOSStub_33f0 {
  strings:
    $key_33f0 = { 67 98 [2] 13 80 [2] 54 82 [2] 13 93 [2] 5d 9f [2] 51 95 [2] 46 9e [2] 5d d0 [2] 60 }

  condition:
    any of them
}