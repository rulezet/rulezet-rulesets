rule TTP_XOR_MULT_DOSStub_4f70 {
  strings:
    $key_4f70 = { 1b 18 [2] 6f 00 [2] 28 02 [2] 6f 13 [2] 21 1f [2] 2d 15 [2] 3a 1e [2] 21 50 [2] 1c }

  condition:
    any of them
}