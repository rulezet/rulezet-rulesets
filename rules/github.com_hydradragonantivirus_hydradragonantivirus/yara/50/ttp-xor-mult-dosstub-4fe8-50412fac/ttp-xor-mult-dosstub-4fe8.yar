rule TTP_XOR_MULT_DOSStub_4fe8 {
  strings:
    $key_4fe8 = { 1b 80 [2] 6f 98 [2] 28 9a [2] 6f 8b [2] 21 87 [2] 2d 8d [2] 3a 86 [2] 21 c8 [2] 1c }

  condition:
    any of them
}