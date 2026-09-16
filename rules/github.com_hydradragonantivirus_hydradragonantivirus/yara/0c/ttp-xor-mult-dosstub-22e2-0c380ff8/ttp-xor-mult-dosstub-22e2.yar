rule TTP_XOR_MULT_DOSStub_22e2 {
  strings:
    $key_22e2 = { 76 8a [2] 02 92 [2] 45 90 [2] 02 81 [2] 4c 8d [2] 40 87 [2] 57 8c [2] 4c c2 [2] 71 }

  condition:
    any of them
}