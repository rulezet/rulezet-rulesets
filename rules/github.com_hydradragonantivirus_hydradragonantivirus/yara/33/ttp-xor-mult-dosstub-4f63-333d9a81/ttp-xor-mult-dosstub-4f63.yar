rule TTP_XOR_MULT_DOSStub_4f63 {
  strings:
    $key_4f63 = { 1b 0b [2] 6f 13 [2] 28 11 [2] 6f 00 [2] 21 0c [2] 2d 06 [2] 3a 0d [2] 21 43 [2] 1c }

  condition:
    any of them
}