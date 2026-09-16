rule TTP_XOR_MULT_DOSStub_4f11 {
  strings:
    $key_4f11 = { 1b 79 [2] 6f 61 [2] 28 63 [2] 6f 72 [2] 21 7e [2] 2d 74 [2] 3a 7f [2] 21 31 [2] 1c }

  condition:
    any of them
}