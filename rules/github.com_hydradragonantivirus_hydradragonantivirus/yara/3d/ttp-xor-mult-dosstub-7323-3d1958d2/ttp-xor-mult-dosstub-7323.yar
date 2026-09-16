rule TTP_XOR_MULT_DOSStub_7323 {
  strings:
    $key_7323 = { 27 4b [2] 53 53 [2] 14 51 [2] 53 40 [2] 1d 4c [2] 11 46 [2] 06 4d [2] 1d 03 [2] 20 }

  condition:
    any of them
}