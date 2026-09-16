rule TTP_XOR_MULT_DOSStub_5714 {
  strings:
    $key_5714 = { 03 7c [2] 77 64 [2] 30 66 [2] 77 77 [2] 39 7b [2] 35 71 [2] 22 7a [2] 39 34 [2] 04 }

  condition:
    any of them
}