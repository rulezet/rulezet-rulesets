rule TTP_XOR_MULT_DOSStub_3014 {
  strings:
    $key_3014 = { 64 7c [2] 10 64 [2] 57 66 [2] 10 77 [2] 5e 7b [2] 52 71 [2] 45 7a [2] 5e 34 [2] 63 }

  condition:
    any of them
}