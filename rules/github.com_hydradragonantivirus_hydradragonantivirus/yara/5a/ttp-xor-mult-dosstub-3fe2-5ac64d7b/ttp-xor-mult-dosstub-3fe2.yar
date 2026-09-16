rule TTP_XOR_MULT_DOSStub_3fe2 {
  strings:
    $key_3fe2 = { 6b 8a [2] 1f 92 [2] 58 90 [2] 1f 81 [2] 51 8d [2] 5d 87 [2] 4a 8c [2] 51 c2 [2] 6c }

  condition:
    any of them
}