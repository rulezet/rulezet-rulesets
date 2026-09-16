rule TTP_XOR_MULT_DOSStub_13f1 {
  strings:
    $key_13f1 = { 47 99 [2] 33 81 [2] 74 83 [2] 33 92 [2] 7d 9e [2] 71 94 [2] 66 9f [2] 7d d1 [2] 40 }

  condition:
    any of them
}