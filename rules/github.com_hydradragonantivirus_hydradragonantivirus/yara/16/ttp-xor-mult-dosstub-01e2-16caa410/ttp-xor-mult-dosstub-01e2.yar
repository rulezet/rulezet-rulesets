rule TTP_XOR_MULT_DOSStub_01e2 {
  strings:
    $key_01e2 = { 55 8a [2] 21 92 [2] 66 90 [2] 21 81 [2] 6f 8d [2] 63 87 [2] 74 8c [2] 6f c2 [2] 52 }

  condition:
    any of them
}