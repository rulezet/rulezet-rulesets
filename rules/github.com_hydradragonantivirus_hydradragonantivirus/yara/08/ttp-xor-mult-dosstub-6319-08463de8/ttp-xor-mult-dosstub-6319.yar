rule TTP_XOR_MULT_DOSStub_6319 {
  strings:
    $key_6319 = { 37 71 [2] 43 69 [2] 04 6b [2] 43 7a [2] 0d 76 [2] 01 7c [2] 16 77 [2] 0d 39 [2] 30 }

  condition:
    any of them
}