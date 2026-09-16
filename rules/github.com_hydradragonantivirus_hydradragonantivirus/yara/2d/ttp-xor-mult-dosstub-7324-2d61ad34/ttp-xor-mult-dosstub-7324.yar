rule TTP_XOR_MULT_DOSStub_7324 {
  strings:
    $key_7324 = { 27 4c [2] 53 54 [2] 14 56 [2] 53 47 [2] 1d 4b [2] 11 41 [2] 06 4a [2] 1d 04 [2] 20 }

  condition:
    any of them
}