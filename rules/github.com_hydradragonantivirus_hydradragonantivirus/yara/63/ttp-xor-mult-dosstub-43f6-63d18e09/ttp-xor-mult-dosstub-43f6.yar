rule TTP_XOR_MULT_DOSStub_43f6 {
  strings:
    $key_43f6 = { 17 9e [2] 63 86 [2] 24 84 [2] 63 95 [2] 2d 99 [2] 21 93 [2] 36 98 [2] 2d d6 [2] 10 }

  condition:
    any of them
}