rule TTP_XOR_MULT_DOSStub_4715 {
  strings:
    $key_4715 = { 13 7d [2] 67 65 [2] 20 67 [2] 67 76 [2] 29 7a [2] 25 70 [2] 32 7b [2] 29 35 [2] 14 }

  condition:
    any of them
}