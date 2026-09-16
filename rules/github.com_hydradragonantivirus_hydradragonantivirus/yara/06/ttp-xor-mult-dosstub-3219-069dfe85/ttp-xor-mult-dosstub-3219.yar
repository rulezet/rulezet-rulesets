rule TTP_XOR_MULT_DOSStub_3219 {
  strings:
    $key_3219 = { 66 71 [2] 12 69 [2] 55 6b [2] 12 7a [2] 5c 76 [2] 50 7c [2] 47 77 [2] 5c 39 [2] 61 }

  condition:
    any of them
}