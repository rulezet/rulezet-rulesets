rule TTP_XOR_MULT_DOSStub_6725 {
  strings:
    $key_6725 = { 33 4d [2] 47 55 [2] 00 57 [2] 47 46 [2] 09 4a [2] 05 40 [2] 12 4b [2] 09 05 [2] 34 }

  condition:
    any of them
}