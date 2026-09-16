rule TTP_XOR_MULT_DOSStub_5114 {
  strings:
    $key_5114 = { 05 7c [2] 71 64 [2] 36 66 [2] 71 77 [2] 3f 7b [2] 33 71 [2] 24 7a [2] 3f 34 [2] 02 }

  condition:
    any of them
}