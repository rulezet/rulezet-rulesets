rule TTP_XOR_MULT_DOSStub_5be2 {
  strings:
    $key_5be2 = { 0f 8a [2] 7b 92 [2] 3c 90 [2] 7b 81 [2] 35 8d [2] 39 87 [2] 2e 8c [2] 35 c2 [2] 08 }

  condition:
    any of them
}