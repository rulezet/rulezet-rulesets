rule TTP_XOR_MULT_DOSStub_4304 {
  strings:
    $key_4304 = { 17 6c [2] 63 74 [2] 24 76 [2] 63 67 [2] 2d 6b [2] 21 61 [2] 36 6a [2] 2d 24 [2] 10 }

  condition:
    any of them
}