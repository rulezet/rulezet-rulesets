rule TTP_XOR_MULT_DOSStub_4f65 {
  strings:
    $key_4f65 = { 1b 0d [2] 6f 15 [2] 28 17 [2] 6f 06 [2] 21 0a [2] 2d 00 [2] 3a 0b [2] 21 45 [2] 1c }

  condition:
    any of them
}