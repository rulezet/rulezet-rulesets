rule TTP_XOR_MULT_DOSStub_23e8 {
  strings:
    $key_23e8 = { 77 80 [2] 03 98 [2] 44 9a [2] 03 8b [2] 4d 87 [2] 41 8d [2] 56 86 [2] 4d c8 [2] 70 }

  condition:
    any of them
}