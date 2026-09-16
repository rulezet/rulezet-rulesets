rule TTP_XOR_MULT_DOSStub_57f8 {
  strings:
    $key_57f8 = { 03 90 [2] 77 88 [2] 30 8a [2] 77 9b [2] 39 97 [2] 35 9d [2] 22 96 [2] 39 d8 [2] 04 }

  condition:
    any of them
}