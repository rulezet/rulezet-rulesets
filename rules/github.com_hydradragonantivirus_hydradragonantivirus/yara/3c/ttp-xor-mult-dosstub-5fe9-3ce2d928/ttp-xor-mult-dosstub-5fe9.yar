rule TTP_XOR_MULT_DOSStub_5fe9 {
  strings:
    $key_5fe9 = { 0b 81 [2] 7f 99 [2] 38 9b [2] 7f 8a [2] 31 86 [2] 3d 8c [2] 2a 87 [2] 31 c9 [2] 0c }

  condition:
    any of them
}