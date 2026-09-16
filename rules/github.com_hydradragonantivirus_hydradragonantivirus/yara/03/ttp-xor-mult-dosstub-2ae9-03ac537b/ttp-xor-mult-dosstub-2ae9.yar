rule TTP_XOR_MULT_DOSStub_2ae9 {
  strings:
    $key_2ae9 = { 7e 81 [2] 0a 99 [2] 4d 9b [2] 0a 8a [2] 44 86 [2] 48 8c [2] 5f 87 [2] 44 c9 [2] 79 }

  condition:
    any of them
}