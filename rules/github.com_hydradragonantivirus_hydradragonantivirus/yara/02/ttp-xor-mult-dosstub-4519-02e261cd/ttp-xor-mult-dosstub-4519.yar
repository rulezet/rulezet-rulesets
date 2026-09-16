rule TTP_XOR_MULT_DOSStub_4519 {
  strings:
    $key_4519 = { 11 71 [2] 65 69 [2] 22 6b [2] 65 7a [2] 2b 76 [2] 27 7c [2] 30 77 [2] 2b 39 [2] 16 }

  condition:
    any of them
}