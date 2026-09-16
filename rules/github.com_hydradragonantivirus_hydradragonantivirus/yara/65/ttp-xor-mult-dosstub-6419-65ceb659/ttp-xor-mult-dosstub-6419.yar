rule TTP_XOR_MULT_DOSStub_6419 {
  strings:
    $key_6419 = { 30 71 [2] 44 69 [2] 03 6b [2] 44 7a [2] 0a 76 [2] 06 7c [2] 11 77 [2] 0a 39 [2] 37 }

  condition:
    any of them
}