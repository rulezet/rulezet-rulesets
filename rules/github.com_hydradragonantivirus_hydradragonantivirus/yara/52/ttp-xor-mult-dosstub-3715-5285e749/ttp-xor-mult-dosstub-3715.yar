rule TTP_XOR_MULT_DOSStub_3715 {
  strings:
    $key_3715 = { 63 7d [2] 17 65 [2] 50 67 [2] 17 76 [2] 59 7a [2] 55 70 [2] 42 7b [2] 59 35 [2] 64 }

  condition:
    any of them
}