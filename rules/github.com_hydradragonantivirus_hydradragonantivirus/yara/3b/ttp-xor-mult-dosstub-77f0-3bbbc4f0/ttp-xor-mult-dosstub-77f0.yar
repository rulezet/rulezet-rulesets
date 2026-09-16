rule TTP_XOR_MULT_DOSStub_77f0 {
  strings:
    $key_77f0 = { 23 98 [2] 57 80 [2] 10 82 [2] 57 93 [2] 19 9f [2] 15 95 [2] 02 9e [2] 19 d0 [2] 24 }

  condition:
    any of them
}