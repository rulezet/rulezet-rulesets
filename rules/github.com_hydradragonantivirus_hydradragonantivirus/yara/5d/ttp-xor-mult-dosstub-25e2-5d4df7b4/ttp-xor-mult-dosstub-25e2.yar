rule TTP_XOR_MULT_DOSStub_25e2 {
  strings:
    $key_25e2 = { 71 8a [2] 05 92 [2] 42 90 [2] 05 81 [2] 4b 8d [2] 47 87 [2] 50 8c [2] 4b c2 [2] 76 }

  condition:
    any of them
}