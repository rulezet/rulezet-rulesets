rule TTP_XOR_MULT_DOSStub_45e2 {
  strings:
    $key_45e2 = { 11 8a [2] 65 92 [2] 22 90 [2] 65 81 [2] 2b 8d [2] 27 87 [2] 30 8c [2] 2b c2 [2] 16 }

  condition:
    any of them
}