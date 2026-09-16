rule TTP_XOR_MULT_DOSStub_07f0 {
  strings:
    $key_07f0 = { 53 98 [2] 27 80 [2] 60 82 [2] 27 93 [2] 69 9f [2] 65 95 [2] 72 9e [2] 69 d0 [2] 54 }

  condition:
    any of them
}