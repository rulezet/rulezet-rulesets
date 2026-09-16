rule TTP_XOR_MULT_DOSStub_23f9 {
  strings:
    $key_23f9 = { 77 91 [2] 03 89 [2] 44 8b [2] 03 9a [2] 4d 96 [2] 41 9c [2] 56 97 [2] 4d d9 [2] 70 }

  condition:
    any of them
}