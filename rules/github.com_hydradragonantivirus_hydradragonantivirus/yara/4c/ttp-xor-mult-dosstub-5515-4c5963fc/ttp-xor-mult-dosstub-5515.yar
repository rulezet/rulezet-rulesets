rule TTP_XOR_MULT_DOSStub_5515 {
  strings:
    $key_5515 = { 01 7d [2] 75 65 [2] 32 67 [2] 75 76 [2] 3b 7a [2] 37 70 [2] 20 7b [2] 3b 35 [2] 06 }

  condition:
    any of them
}