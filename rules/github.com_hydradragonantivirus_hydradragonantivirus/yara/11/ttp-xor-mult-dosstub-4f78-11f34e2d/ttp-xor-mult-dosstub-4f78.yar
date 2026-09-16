rule TTP_XOR_MULT_DOSStub_4f78 {
  strings:
    $key_4f78 = { 1b 10 [2] 6f 08 [2] 28 0a [2] 6f 1b [2] 21 17 [2] 2d 1d [2] 3a 16 [2] 21 58 [2] 1c }

  condition:
    any of them
}