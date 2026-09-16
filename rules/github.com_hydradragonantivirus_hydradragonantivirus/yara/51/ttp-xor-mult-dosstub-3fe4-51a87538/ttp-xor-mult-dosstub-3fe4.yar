rule TTP_XOR_MULT_DOSStub_3fe4 {
  strings:
    $key_3fe4 = { 6b 8c [2] 1f 94 [2] 58 96 [2] 1f 87 [2] 51 8b [2] 5d 81 [2] 4a 8a [2] 51 c4 [2] 6c }

  condition:
    any of them
}