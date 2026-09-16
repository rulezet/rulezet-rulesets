rule TTP_XOR_MULT_DOSStub_4f18 {
  strings:
    $key_4f18 = { 1b 70 [2] 6f 68 [2] 28 6a [2] 6f 7b [2] 21 77 [2] 2d 7d [2] 3a 76 [2] 21 38 [2] 1c }

  condition:
    any of them
}