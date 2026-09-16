rule TTP_XOR_MULT_DOSStub_52f0 {
  strings:
    $key_52f0 = { 06 98 [2] 72 80 [2] 35 82 [2] 72 93 [2] 3c 9f [2] 30 95 [2] 27 9e [2] 3c d0 [2] 01 }

  condition:
    any of them
}