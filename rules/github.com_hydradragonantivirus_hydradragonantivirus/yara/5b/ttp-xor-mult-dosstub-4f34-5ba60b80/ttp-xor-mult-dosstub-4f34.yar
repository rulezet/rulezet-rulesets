rule TTP_XOR_MULT_DOSStub_4f34 {
  strings:
    $key_4f34 = { 1b 5c [2] 6f 44 [2] 28 46 [2] 6f 57 [2] 21 5b [2] 2d 51 [2] 3a 5a [2] 21 14 [2] 1c }

  condition:
    any of them
}