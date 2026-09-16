rule TTP_XOR_MULT_DOSStub_7de2 {
  strings:
    $key_7de2 = { 29 8a [2] 5d 92 [2] 1a 90 [2] 5d 81 [2] 13 8d [2] 1f 87 [2] 08 8c [2] 13 c2 [2] 2e }

  condition:
    any of them
}