rule TTP_XOR_MULT_DOSStub_7114 {
  strings:
    $key_7114 = { 25 7c [2] 51 64 [2] 16 66 [2] 51 77 [2] 1f 7b [2] 13 71 [2] 04 7a [2] 1f 34 [2] 22 }

  condition:
    any of them
}