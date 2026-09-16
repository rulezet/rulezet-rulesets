rule TTP_XOR_MULT_DOSStub_4f73 {
  strings:
    $key_4f73 = { 1b 1b [2] 6f 03 [2] 28 01 [2] 6f 10 [2] 21 1c [2] 2d 16 [2] 3a 1d [2] 21 53 [2] 1c }

  condition:
    any of them
}