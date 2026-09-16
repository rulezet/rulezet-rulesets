rule TTP_XOR_MULT_DOSStub_4643 {
  strings:
    $key_4643 = { 12 2b [2] 66 33 [2] 21 31 [2] 66 20 [2] 28 2c [2] 24 26 [2] 33 2d [2] 28 63 [2] 15 }

  condition:
    any of them
}