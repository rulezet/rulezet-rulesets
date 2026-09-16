rule TTP_XOR_MULT_DOSStub_33e5 {
  strings:
    $key_33e5 = { 67 8d [2] 13 95 [2] 54 97 [2] 13 86 [2] 5d 8a [2] 51 80 [2] 46 8b [2] 5d c5 [2] 60 }

  condition:
    any of them
}