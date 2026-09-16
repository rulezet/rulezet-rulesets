rule TTP_XOR_MULT_DOSStub_23f4 {
  strings:
    $key_23f4 = { 77 9c [2] 03 84 [2] 44 86 [2] 03 97 [2] 4d 9b [2] 41 91 [2] 56 9a [2] 4d d4 [2] 70 }

  condition:
    any of them
}