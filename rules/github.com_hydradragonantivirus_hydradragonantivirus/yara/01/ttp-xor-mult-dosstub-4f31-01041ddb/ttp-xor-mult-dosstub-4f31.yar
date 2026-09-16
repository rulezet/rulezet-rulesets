rule TTP_XOR_MULT_DOSStub_4f31 {
  strings:
    $key_4f31 = { 1b 59 [2] 6f 41 [2] 28 43 [2] 6f 52 [2] 21 5e [2] 2d 54 [2] 3a 5f [2] 21 11 [2] 1c }

  condition:
    any of them
}