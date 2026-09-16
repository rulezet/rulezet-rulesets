rule TTP_XOR_MULT_DOSStub_1635 {
  strings:
    $key_1635 = { 42 5d [2] 36 45 [2] 71 47 [2] 36 56 [2] 78 5a [2] 74 50 [2] 63 5b [2] 78 15 [2] 45 }

  condition:
    any of them
}