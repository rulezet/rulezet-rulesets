rule TTP_XOR_MULT_DOSStub_7325 {
  strings:
    $key_7325 = { 27 4d [2] 53 55 [2] 14 57 [2] 53 46 [2] 1d 4a [2] 11 40 [2] 06 4b [2] 1d 05 [2] 20 }

  condition:
    any of them
}