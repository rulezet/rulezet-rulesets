rule TTP_XOR_MULT_DOSStub_1739 {
  strings:
    $key_1739 = { 43 51 [2] 37 49 [2] 70 4b [2] 37 5a [2] 79 56 [2] 75 5c [2] 62 57 [2] 79 19 [2] 44 }

  condition:
    any of them
}