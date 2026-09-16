rule TTP_XOR_MULT_DOSStub_4f69 {
  strings:
    $key_4f69 = { 1b 01 [2] 6f 19 [2] 28 1b [2] 6f 0a [2] 21 06 [2] 2d 0c [2] 3a 07 [2] 21 49 [2] 1c }

  condition:
    any of them
}