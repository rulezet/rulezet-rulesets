rule TTP_XOR_MULT_DOSStub_2759 {
  strings:
    $key_2759 = { 73 31 [2] 07 29 [2] 40 2b [2] 07 3a [2] 49 36 [2] 45 3c [2] 52 37 [2] 49 79 [2] 74 }

  condition:
    any of them
}