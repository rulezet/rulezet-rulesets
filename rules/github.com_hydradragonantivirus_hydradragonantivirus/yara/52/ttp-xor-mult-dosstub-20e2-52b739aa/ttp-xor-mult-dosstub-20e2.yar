rule TTP_XOR_MULT_DOSStub_20e2 {
  strings:
    $key_20e2 = { 74 8a [2] 00 92 [2] 47 90 [2] 00 81 [2] 4e 8d [2] 42 87 [2] 55 8c [2] 4e c2 [2] 73 }

  condition:
    any of them
}