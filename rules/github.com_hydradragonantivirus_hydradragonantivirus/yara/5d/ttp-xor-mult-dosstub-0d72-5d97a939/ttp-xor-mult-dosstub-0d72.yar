rule TTP_XOR_MULT_DOSStub_0d72 {
  strings:
    $key_0d72 = { 59 1a [2] 2d 02 [2] 6a 00 [2] 2d 11 [2] 63 1d [2] 6f 17 [2] 78 1c [2] 63 52 [2] 5e }

  condition:
    any of them
}