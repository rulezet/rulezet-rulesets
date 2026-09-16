rule TTP_XOR_MULT_DOSStub_62e2 {
  strings:
    $key_62e2 = { 36 8a [2] 42 92 [2] 05 90 [2] 42 81 [2] 0c 8d [2] 00 87 [2] 17 8c [2] 0c c2 [2] 31 }

  condition:
    any of them
}