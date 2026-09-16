rule TTP_XOR_MULT_DOSStub_7305 {
  strings:
    $key_7305 = { 27 6d [2] 53 75 [2] 14 77 [2] 53 66 [2] 1d 6a [2] 11 60 [2] 06 6b [2] 1d 25 [2] 20 }

  condition:
    any of them
}