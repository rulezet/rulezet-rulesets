rule TTP_XOR_MULT_DOSStub_3045 {
  strings:
    $key_3045 = { 64 2d [2] 10 35 [2] 57 37 [2] 10 26 [2] 5e 2a [2] 52 20 [2] 45 2b [2] 5e 65 [2] 63 }

  condition:
    any of them
}