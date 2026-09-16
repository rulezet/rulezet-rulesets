rule TTP_XOR_MULT_DOSStub_5f48 {
  strings:
    $key_5f48 = { 0b 20 [2] 7f 38 [2] 38 3a [2] 7f 2b [2] 31 27 [2] 3d 2d [2] 2a 26 [2] 31 68 [2] 0c }

  condition:
    any of them
}