rule TTP_XOR_MULT_DOSStub_6f72 {
  strings:
    $key_6f72 = { 3b 1a [2] 4f 02 [2] 08 00 [2] 4f 11 [2] 01 1d [2] 0d 17 [2] 1a 1c [2] 01 52 [2] 3c }

  condition:
    any of them
}