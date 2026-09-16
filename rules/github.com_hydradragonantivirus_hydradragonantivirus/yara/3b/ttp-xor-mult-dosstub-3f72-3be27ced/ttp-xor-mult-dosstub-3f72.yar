rule TTP_XOR_MULT_DOSStub_3f72 {
  strings:
    $key_3f72 = { 6b 1a [2] 1f 02 [2] 58 00 [2] 1f 11 [2] 51 1d [2] 5d 17 [2] 4a 1c [2] 51 52 [2] 6c }

  condition:
    any of them
}