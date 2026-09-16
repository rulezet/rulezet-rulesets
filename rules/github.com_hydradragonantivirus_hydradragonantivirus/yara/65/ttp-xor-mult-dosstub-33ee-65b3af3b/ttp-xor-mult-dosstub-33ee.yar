rule TTP_XOR_MULT_DOSStub_33ee {
  strings:
    $key_33ee = { 67 86 [2] 13 9e [2] 54 9c [2] 13 8d [2] 5d 81 [2] 51 8b [2] 46 80 [2] 5d ce [2] 60 }

  condition:
    any of them
}