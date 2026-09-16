rule TTP_XOR_MULT_DOSStub_0d44 {
  strings:
    $key_0d44 = { 59 2c [2] 2d 34 [2] 6a 36 [2] 2d 27 [2] 63 2b [2] 6f 21 [2] 78 2a [2] 63 64 [2] 5e }

  condition:
    any of them
}