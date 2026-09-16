rule TTP_XOR_MULT_DOSStub_7719 {
  strings:
    $key_7719 = { 23 71 [2] 57 69 [2] 10 6b [2] 57 7a [2] 19 76 [2] 15 7c [2] 02 77 [2] 19 39 [2] 24 }

  condition:
    any of them
}