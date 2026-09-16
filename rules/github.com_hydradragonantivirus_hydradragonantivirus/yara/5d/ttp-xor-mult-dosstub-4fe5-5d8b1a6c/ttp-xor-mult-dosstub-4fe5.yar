rule TTP_XOR_MULT_DOSStub_4fe5 {
  strings:
    $key_4fe5 = { 1b 8d [2] 6f 95 [2] 28 97 [2] 6f 86 [2] 21 8a [2] 2d 80 [2] 3a 8b [2] 21 c5 [2] 1c }

  condition:
    any of them
}