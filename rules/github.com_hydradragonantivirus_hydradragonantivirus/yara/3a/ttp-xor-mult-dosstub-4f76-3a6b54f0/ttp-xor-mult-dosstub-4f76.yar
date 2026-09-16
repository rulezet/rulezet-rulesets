rule TTP_XOR_MULT_DOSStub_4f76 {
  strings:
    $key_4f76 = { 1b 1e [2] 6f 06 [2] 28 04 [2] 6f 15 [2] 21 19 [2] 2d 13 [2] 3a 18 [2] 21 56 [2] 1c }

  condition:
    any of them
}