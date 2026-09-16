rule TTP_XOR_MULT_DOSStub_5f49 {
  strings:
    $key_5f49 = { 0b 21 [2] 7f 39 [2] 38 3b [2] 7f 2a [2] 31 26 [2] 3d 2c [2] 2a 27 [2] 31 69 [2] 0c }

  condition:
    any of them
}