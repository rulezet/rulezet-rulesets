rule TTP_XOR_MULT_DOSStub_7313 {
  strings:
    $key_7313 = { 27 7b [2] 53 63 [2] 14 61 [2] 53 70 [2] 1d 7c [2] 11 76 [2] 06 7d [2] 1d 33 [2] 20 }

  condition:
    any of them
}