rule TTP_XOR_MULT_DOSStub_35e2 {
  strings:
    $key_35e2 = { 61 8a [2] 15 92 [2] 52 90 [2] 15 81 [2] 5b 8d [2] 57 87 [2] 40 8c [2] 5b c2 [2] 66 }

  condition:
    any of them
}