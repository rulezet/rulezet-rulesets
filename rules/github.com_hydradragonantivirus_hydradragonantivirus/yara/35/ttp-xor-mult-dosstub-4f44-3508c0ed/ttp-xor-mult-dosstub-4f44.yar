rule TTP_XOR_MULT_DOSStub_4f44 {
  strings:
    $key_4f44 = { 1b 2c [2] 6f 34 [2] 28 36 [2] 6f 27 [2] 21 2b [2] 2d 21 [2] 3a 2a [2] 21 64 [2] 1c }

  condition:
    any of them
}