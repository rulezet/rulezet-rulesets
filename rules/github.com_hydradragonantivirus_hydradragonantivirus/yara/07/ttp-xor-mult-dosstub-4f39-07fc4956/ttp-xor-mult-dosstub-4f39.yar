rule TTP_XOR_MULT_DOSStub_4f39 {
  strings:
    $key_4f39 = { 1b 51 [2] 6f 49 [2] 28 4b [2] 6f 5a [2] 21 56 [2] 2d 5c [2] 3a 57 [2] 21 19 [2] 1c }

  condition:
    any of them
}