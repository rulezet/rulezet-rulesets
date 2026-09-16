rule TTP_XOR_MULT_DOSStub_3719 {
  strings:
    $key_3719 = { 63 71 [2] 17 69 [2] 50 6b [2] 17 7a [2] 59 76 [2] 55 7c [2] 42 77 [2] 59 39 [2] 64 }

  condition:
    any of them
}