rule TTP_XOR_MULT_DOSStub_23f6 {
  strings:
    $key_23f6 = { 77 9e [2] 03 86 [2] 44 84 [2] 03 95 [2] 4d 99 [2] 41 93 [2] 56 98 [2] 4d d6 [2] 70 }

  condition:
    any of them
}