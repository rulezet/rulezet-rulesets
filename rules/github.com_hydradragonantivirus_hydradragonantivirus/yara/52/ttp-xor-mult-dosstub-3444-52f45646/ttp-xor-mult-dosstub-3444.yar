rule TTP_XOR_MULT_DOSStub_3444 {
  strings:
    $key_3444 = { 60 2c [2] 14 34 [2] 53 36 [2] 14 27 [2] 5a 2b [2] 56 21 [2] 41 2a [2] 5a 64 [2] 67 }

  condition:
    any of them
}