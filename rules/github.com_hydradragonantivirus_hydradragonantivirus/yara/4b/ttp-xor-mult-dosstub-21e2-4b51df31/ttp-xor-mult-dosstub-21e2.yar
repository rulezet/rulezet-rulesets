rule TTP_XOR_MULT_DOSStub_21e2 {
  strings:
    $key_21e2 = { 75 8a [2] 01 92 [2] 46 90 [2] 01 81 [2] 4f 8d [2] 43 87 [2] 54 8c [2] 4f c2 [2] 72 }

  condition:
    any of them
}