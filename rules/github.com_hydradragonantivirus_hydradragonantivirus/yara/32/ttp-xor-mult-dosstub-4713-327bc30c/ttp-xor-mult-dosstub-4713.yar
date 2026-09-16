rule TTP_XOR_MULT_DOSStub_4713 {
  strings:
    $key_4713 = { 13 7b [2] 67 63 [2] 20 61 [2] 67 70 [2] 29 7c [2] 25 76 [2] 32 7d [2] 29 33 [2] 14 }

  condition:
    any of them
}