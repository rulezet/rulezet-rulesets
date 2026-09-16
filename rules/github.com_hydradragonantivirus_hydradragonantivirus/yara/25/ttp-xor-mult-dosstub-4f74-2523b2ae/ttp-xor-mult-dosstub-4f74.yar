rule TTP_XOR_MULT_DOSStub_4f74 {
  strings:
    $key_4f74 = { 1b 1c [2] 6f 04 [2] 28 06 [2] 6f 17 [2] 21 1b [2] 2d 11 [2] 3a 1a [2] 21 54 [2] 1c }

  condition:
    any of them
}