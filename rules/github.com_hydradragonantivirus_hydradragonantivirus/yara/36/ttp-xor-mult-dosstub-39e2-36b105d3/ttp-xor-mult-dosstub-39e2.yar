rule TTP_XOR_MULT_DOSStub_39e2 {
  strings:
    $key_39e2 = { 6d 8a [2] 19 92 [2] 5e 90 [2] 19 81 [2] 57 8d [2] 5b 87 [2] 4c 8c [2] 57 c2 [2] 6a }

  condition:
    any of them
}