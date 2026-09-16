rule TTP_XOR_MULT_DOSStub_6f48 {
  strings:
    $key_6f48 = { 3b 20 [2] 4f 38 [2] 08 3a [2] 4f 2b [2] 01 27 [2] 0d 2d [2] 1a 26 [2] 01 68 [2] 3c }

  condition:
    any of them
}