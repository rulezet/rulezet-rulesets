rule TTP_XOR_MULT_DOSStub_5219 {
  strings:
    $key_5219 = { 06 71 [2] 72 69 [2] 35 6b [2] 72 7a [2] 3c 76 [2] 30 7c [2] 27 77 [2] 3c 39 [2] 01 }

  condition:
    any of them
}