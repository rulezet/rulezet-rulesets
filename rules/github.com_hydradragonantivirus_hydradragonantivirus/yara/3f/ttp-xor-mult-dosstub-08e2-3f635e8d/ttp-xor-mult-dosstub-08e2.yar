rule TTP_XOR_MULT_DOSStub_08e2 {
  strings:
    $key_08e2 = { 5c 8a [2] 28 92 [2] 6f 90 [2] 28 81 [2] 66 8d [2] 6a 87 [2] 7d 8c [2] 66 c2 [2] 5b }

  condition:
    any of them
}