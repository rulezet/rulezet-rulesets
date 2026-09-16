rule TTP_XOR_MULT_DOSStub_23e3 {
  strings:
    $key_23e3 = { 77 8b [2] 03 93 [2] 44 91 [2] 03 80 [2] 4d 8c [2] 41 86 [2] 56 8d [2] 4d c3 [2] 70 }

  condition:
    any of them
}