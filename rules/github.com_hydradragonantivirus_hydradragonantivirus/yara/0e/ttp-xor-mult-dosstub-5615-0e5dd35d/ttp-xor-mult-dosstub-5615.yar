rule TTP_XOR_MULT_DOSStub_5615 {
  strings:
    $key_5615 = { 02 7d [2] 76 65 [2] 31 67 [2] 76 76 [2] 38 7a [2] 34 70 [2] 23 7b [2] 38 35 [2] 05 }

  condition:
    any of them
}