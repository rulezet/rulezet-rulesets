rule TTP_XOR_MULT_DOSStub_63f6 {
  strings:
    $key_63f6 = { 37 9e [2] 43 86 [2] 04 84 [2] 43 95 [2] 0d 99 [2] 01 93 [2] 16 98 [2] 0d d6 [2] 30 }

  condition:
    any of them
}