rule TTP_XOR_MULT_DOSStub_5659 {
  strings:
    $key_5659 = { 02 31 [2] 76 29 [2] 31 2b [2] 76 3a [2] 38 36 [2] 34 3c [2] 23 37 [2] 38 79 [2] 05 }

  condition:
    any of them
}