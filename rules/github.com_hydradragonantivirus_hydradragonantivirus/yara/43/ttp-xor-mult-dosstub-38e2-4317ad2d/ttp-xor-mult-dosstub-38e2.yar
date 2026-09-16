rule TTP_XOR_MULT_DOSStub_38e2 {
  strings:
    $key_38e2 = { 6c 8a [2] 18 92 [2] 5f 90 [2] 18 81 [2] 56 8d [2] 5a 87 [2] 4d 8c [2] 56 c2 [2] 6b }

  condition:
    any of them
}