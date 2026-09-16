rule TTP_XOR_MULT_DOSStub_2614 {
  strings:
    $key_2614 = { 72 7c [2] 06 64 [2] 41 66 [2] 06 77 [2] 48 7b [2] 44 71 [2] 53 7a [2] 48 34 [2] 75 }

  condition:
    any of them
}