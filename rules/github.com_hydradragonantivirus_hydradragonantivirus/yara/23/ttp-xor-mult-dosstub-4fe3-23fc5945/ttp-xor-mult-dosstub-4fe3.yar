rule TTP_XOR_MULT_DOSStub_4fe3 {
  strings:
    $key_4fe3 = { 1b 8b [2] 6f 93 [2] 28 91 [2] 6f 80 [2] 21 8c [2] 2d 86 [2] 3a 8d [2] 21 c3 [2] 1c }

  condition:
    any of them
}