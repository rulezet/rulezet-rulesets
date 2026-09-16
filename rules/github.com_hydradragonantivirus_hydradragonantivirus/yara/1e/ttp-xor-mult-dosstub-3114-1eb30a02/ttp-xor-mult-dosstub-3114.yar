rule TTP_XOR_MULT_DOSStub_3114 {
  strings:
    $key_3114 = { 65 7c [2] 11 64 [2] 56 66 [2] 11 77 [2] 5f 7b [2] 53 71 [2] 44 7a [2] 5f 34 [2] 62 }

  condition:
    any of them
}