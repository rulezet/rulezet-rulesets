rule TTP_XOR_MULT_DOSStub_2754 {
  strings:
    $key_2754 = { 73 3c [2] 07 24 [2] 40 26 [2] 07 37 [2] 49 3b [2] 45 31 [2] 52 3a [2] 49 74 [2] 74 }

  condition:
    any of them
}