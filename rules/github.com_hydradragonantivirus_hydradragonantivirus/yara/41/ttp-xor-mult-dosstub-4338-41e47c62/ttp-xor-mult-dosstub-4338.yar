rule TTP_XOR_MULT_DOSStub_4338 {
  strings:
    $key_4338 = { 17 50 [2] 63 48 [2] 24 4a [2] 63 5b [2] 2d 57 [2] 21 5d [2] 36 56 [2] 2d 18 [2] 10 }

  condition:
    any of them
}