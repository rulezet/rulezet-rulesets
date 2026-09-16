rule TTP_XOR_MULT_DOSStub_4f45 {
  strings:
    $key_4f45 = { 1b 2d [2] 6f 35 [2] 28 37 [2] 6f 26 [2] 21 2a [2] 2d 20 [2] 3a 2b [2] 21 65 [2] 1c }

  condition:
    any of them
}