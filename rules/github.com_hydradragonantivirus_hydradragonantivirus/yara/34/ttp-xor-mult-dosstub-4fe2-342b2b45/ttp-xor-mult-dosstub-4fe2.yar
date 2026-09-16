rule TTP_XOR_MULT_DOSStub_4fe2 {
  strings:
    $key_4fe2 = { 1b 8a [2] 6f 92 [2] 28 90 [2] 6f 81 [2] 21 8d [2] 2d 87 [2] 3a 8c [2] 21 c2 [2] 1c }

  condition:
    any of them
}