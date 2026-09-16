rule TTP_XOR_MULT_DOSStub_72e2 {
  strings:
    $key_72e2 = { 26 8a [2] 52 92 [2] 15 90 [2] 52 81 [2] 1c 8d [2] 10 87 [2] 07 8c [2] 1c c2 [2] 21 }

  condition:
    any of them
}