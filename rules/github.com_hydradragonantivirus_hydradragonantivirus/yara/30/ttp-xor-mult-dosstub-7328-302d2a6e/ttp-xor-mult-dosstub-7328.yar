rule TTP_XOR_MULT_DOSStub_7328 {
  strings:
    $key_7328 = { 27 40 [2] 53 58 [2] 14 5a [2] 53 4b [2] 1d 47 [2] 11 4d [2] 06 46 [2] 1d 08 [2] 20 }

  condition:
    any of them
}