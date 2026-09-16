rule TTP_XOR_MULT_DOSStub_1ae2 {
  strings:
    $key_1ae2 = { 4e 8a [2] 3a 92 [2] 7d 90 [2] 3a 81 [2] 74 8d [2] 78 87 [2] 6f 8c [2] 74 c2 [2] 49 }

  condition:
    any of them
}