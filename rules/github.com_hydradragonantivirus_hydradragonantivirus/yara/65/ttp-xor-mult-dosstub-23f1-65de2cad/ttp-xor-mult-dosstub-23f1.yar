rule TTP_XOR_MULT_DOSStub_23f1 {
  strings:
    $key_23f1 = { 77 99 [2] 03 81 [2] 44 83 [2] 03 92 [2] 4d 9e [2] 41 94 [2] 56 9f [2] 4d d1 [2] 70 }

  condition:
    any of them
}