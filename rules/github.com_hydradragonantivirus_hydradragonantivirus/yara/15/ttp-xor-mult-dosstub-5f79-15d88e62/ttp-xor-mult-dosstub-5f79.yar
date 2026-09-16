rule TTP_XOR_MULT_DOSStub_5f79 {
  strings:
    $key_5f79 = { 0b 11 [2] 7f 09 [2] 38 0b [2] 7f 1a [2] 31 16 [2] 3d 1c [2] 2a 17 [2] 31 59 [2] 0c }

  condition:
    any of them
}