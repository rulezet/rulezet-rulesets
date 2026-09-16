rule TTP_XOR_MULT_DOSStub_3fe9 {
  strings:
    $key_3fe9 = { 6b 81 [2] 1f 99 [2] 58 9b [2] 1f 8a [2] 51 86 [2] 5d 8c [2] 4a 87 [2] 51 c9 [2] 6c }

  condition:
    any of them
}