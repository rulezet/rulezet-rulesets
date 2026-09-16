rule TTP_XOR_MULT_DOSStub_5276 {
  strings:
    $key_5276 = { 06 1e [2] 72 06 [2] 35 04 [2] 72 15 [2] 3c 19 [2] 30 13 [2] 27 18 [2] 3c 56 [2] 01 }

  condition:
    any of them
}