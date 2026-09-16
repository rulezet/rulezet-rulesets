rule TTP_XOR_MULT_DOSStub_5f55 {
  strings:
    $key_5f55 = { 0b 3d [2] 7f 25 [2] 38 27 [2] 7f 36 [2] 31 3a [2] 3d 30 [2] 2a 3b [2] 31 75 [2] 0c }

  condition:
    any of them
}