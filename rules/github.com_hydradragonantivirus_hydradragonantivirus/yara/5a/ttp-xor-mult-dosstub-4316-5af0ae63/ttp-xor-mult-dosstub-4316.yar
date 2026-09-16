rule TTP_XOR_MULT_DOSStub_4316 {
  strings:
    $key_4316 = { 17 7e [2] 63 66 [2] 24 64 [2] 63 75 [2] 2d 79 [2] 21 73 [2] 36 78 [2] 2d 36 [2] 10 }

  condition:
    any of them
}