rule TTP_XOR_MULT_DOSStub_6fe9 {
  strings:
    $key_6fe9 = { 3b 81 [2] 4f 99 [2] 08 9b [2] 4f 8a [2] 01 86 [2] 0d 8c [2] 1a 87 [2] 01 c9 [2] 3c }

  condition:
    any of them
}