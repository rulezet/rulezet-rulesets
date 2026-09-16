rule TTP_XOR_MULT_DOSStub_63f0 {
  strings:
    $key_63f0 = { 37 98 [2] 43 80 [2] 04 82 [2] 43 93 [2] 0d 9f [2] 01 95 [2] 16 9e [2] 0d d0 [2] 30 }

  condition:
    any of them
}