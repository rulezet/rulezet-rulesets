rule TTP_XOR_MULT_DOSStub_1613 {
  strings:
    $key_1613 = { 42 7b [2] 36 63 [2] 71 61 [2] 36 70 [2] 78 7c [2] 74 76 [2] 63 7d [2] 78 33 [2] 45 }

  condition:
    any of them
}