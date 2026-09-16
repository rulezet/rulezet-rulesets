rule TTP_XOR_MULT_DOSStub_0d43 {
  strings:
    $key_0d43 = { 59 2b [2] 2d 33 [2] 6a 31 [2] 2d 20 [2] 63 2c [2] 6f 26 [2] 78 2d [2] 63 63 [2] 5e }

  condition:
    any of them
}