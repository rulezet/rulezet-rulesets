rule TTP_XOR_MULT_DOSStub_4f43 {
  strings:
    $key_4f43 = { 1b 2b [2] 6f 33 [2] 28 31 [2] 6f 20 [2] 21 2c [2] 2d 26 [2] 3a 2d [2] 21 63 [2] 1c }

  condition:
    any of them
}