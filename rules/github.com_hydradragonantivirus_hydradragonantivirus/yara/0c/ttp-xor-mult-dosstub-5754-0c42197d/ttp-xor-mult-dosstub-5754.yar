rule TTP_XOR_MULT_DOSStub_5754 {
  strings:
    $key_5754 = { 03 3c [2] 77 24 [2] 30 26 [2] 77 37 [2] 39 3b [2] 35 31 [2] 22 3a [2] 39 74 [2] 04 }

  condition:
    any of them
}