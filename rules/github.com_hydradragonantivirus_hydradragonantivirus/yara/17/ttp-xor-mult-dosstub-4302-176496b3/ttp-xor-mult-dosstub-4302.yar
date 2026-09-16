rule TTP_XOR_MULT_DOSStub_4302 {
  strings:
    $key_4302 = { 17 6a [2] 63 72 [2] 24 70 [2] 63 61 [2] 2d 6d [2] 21 67 [2] 36 6c [2] 2d 22 [2] 10 }

  condition:
    any of them
}