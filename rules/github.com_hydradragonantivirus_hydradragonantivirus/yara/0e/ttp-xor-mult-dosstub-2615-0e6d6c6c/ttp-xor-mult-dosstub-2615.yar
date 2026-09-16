rule TTP_XOR_MULT_DOSStub_2615 {
  strings:
    $key_2615 = { 72 7d [2] 06 65 [2] 41 67 [2] 06 76 [2] 48 7a [2] 44 70 [2] 53 7b [2] 48 35 [2] 75 }

  condition:
    any of them
}