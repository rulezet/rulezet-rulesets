rule TTP_XOR_MULT_DOSStub_7be2 {
  strings:
    $key_7be2 = { 2f 8a [2] 5b 92 [2] 1c 90 [2] 5b 81 [2] 15 8d [2] 19 87 [2] 0e 8c [2] 15 c2 [2] 28 }

  condition:
    any of them
}