rule TTP_XOR_MULT_DOSStub_4f19 {
  strings:
    $key_4f19 = { 1b 71 [2] 6f 69 [2] 28 6b [2] 6f 7a [2] 21 76 [2] 2d 7c [2] 3a 77 [2] 21 39 [2] 1c }

  condition:
    any of them
}