rule TTP_XOR_MULT_DOSStub_7322 {
  strings:
    $key_7322 = { 27 4a [2] 53 52 [2] 14 50 [2] 53 41 [2] 1d 4d [2] 11 47 [2] 06 4c [2] 1d 02 [2] 20 }

  condition:
    any of them
}