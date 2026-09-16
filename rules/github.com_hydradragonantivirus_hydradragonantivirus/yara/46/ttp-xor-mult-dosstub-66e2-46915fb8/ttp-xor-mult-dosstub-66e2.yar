rule TTP_XOR_MULT_DOSStub_66e2 {
  strings:
    $key_66e2 = { 32 8a [2] 46 92 [2] 01 90 [2] 46 81 [2] 08 8d [2] 04 87 [2] 13 8c [2] 08 c2 [2] 35 }

  condition:
    any of them
}