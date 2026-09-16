rule TTP_XOR_MULT_DOSStub_e8e2 {
  strings:
    $key_e8e2 = { bc 8a [2] c8 92 [2] 8f 90 [2] c8 81 [2] 86 8d [2] 8a 87 [2] 9d 8c [2] 86 c2 [2] bb }

  condition:
    any of them
}