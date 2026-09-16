rule TTP_XOR_MULT_DOSStub_4f06 {
  strings:
    $key_4f06 = { 1b 6e [2] 6f 76 [2] 28 74 [2] 6f 65 [2] 21 69 [2] 2d 63 [2] 3a 68 [2] 21 26 [2] 1c }

  condition:
    any of them
}