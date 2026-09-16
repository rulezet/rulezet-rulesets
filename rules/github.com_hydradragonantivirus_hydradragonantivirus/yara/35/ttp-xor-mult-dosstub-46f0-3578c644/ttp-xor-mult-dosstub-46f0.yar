rule TTP_XOR_MULT_DOSStub_46f0 {
  strings:
    $key_46f0 = { 12 98 [2] 66 80 [2] 21 82 [2] 66 93 [2] 28 9f [2] 24 95 [2] 33 9e [2] 28 d0 [2] 15 }

  condition:
    any of them
}