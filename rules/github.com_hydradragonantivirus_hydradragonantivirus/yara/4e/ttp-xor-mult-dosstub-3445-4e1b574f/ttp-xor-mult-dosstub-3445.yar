rule TTP_XOR_MULT_DOSStub_3445 {
  strings:
    $key_3445 = { 60 2d [2] 14 35 [2] 53 37 [2] 14 26 [2] 5a 2a [2] 56 20 [2] 41 2b [2] 5a 65 [2] 67 }

  condition:
    any of them
}