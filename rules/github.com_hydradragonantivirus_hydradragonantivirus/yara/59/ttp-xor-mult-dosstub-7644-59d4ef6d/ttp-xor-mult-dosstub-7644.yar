rule TTP_XOR_MULT_DOSStub_7644 {
  strings:
    $key_7644 = { 22 2c [2] 56 34 [2] 11 36 [2] 56 27 [2] 18 2b [2] 14 21 [2] 03 2a [2] 18 64 [2] 25 }

  condition:
    any of them
}