rule TTP_XOR_MULT_DOSStub_2fe9 {
  strings:
    $key_2fe9 = { 7b 81 [2] 0f 99 [2] 48 9b [2] 0f 8a [2] 41 86 [2] 4d 8c [2] 5a 87 [2] 41 c9 [2] 7c }

  condition:
    any of them
}