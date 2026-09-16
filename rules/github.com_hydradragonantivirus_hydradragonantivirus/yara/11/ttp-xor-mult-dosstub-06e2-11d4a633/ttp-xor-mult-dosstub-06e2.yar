rule TTP_XOR_MULT_DOSStub_06e2 {
  strings:
    $key_06e2 = { 52 8a [2] 26 92 [2] 61 90 [2] 26 81 [2] 68 8d [2] 64 87 [2] 73 8c [2] 68 c2 [2] 55 }

  condition:
    any of them
}