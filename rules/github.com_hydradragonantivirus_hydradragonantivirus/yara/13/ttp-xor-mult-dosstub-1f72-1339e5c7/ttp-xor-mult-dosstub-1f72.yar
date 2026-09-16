rule TTP_XOR_MULT_DOSStub_1f72 {
  strings:
    $key_1f72 = { 4b 1a [2] 3f 02 [2] 78 00 [2] 3f 11 [2] 71 1d [2] 7d 17 [2] 6a 1c [2] 71 52 [2] 4c }

  condition:
    any of them
}