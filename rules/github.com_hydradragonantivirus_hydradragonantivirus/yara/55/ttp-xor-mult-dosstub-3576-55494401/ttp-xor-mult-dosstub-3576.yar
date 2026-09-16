rule TTP_XOR_MULT_DOSStub_3576 {
  strings:
    $key_3576 = { 61 1e [2] 15 06 [2] 52 04 [2] 15 15 [2] 5b 19 [2] 57 13 [2] 40 18 [2] 5b 56 [2] 66 }

  condition:
    any of them
}