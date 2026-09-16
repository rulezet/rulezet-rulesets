rule TTP_XOR_MULT_DOSStub_64f0 {
  strings:
    $key_64f0 = { 30 98 [2] 44 80 [2] 03 82 [2] 44 93 [2] 0a 9f [2] 06 95 [2] 11 9e [2] 0a d0 [2] 37 }

  condition:
    any of them
}