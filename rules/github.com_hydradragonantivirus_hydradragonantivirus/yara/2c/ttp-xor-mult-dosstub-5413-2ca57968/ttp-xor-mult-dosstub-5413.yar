rule TTP_XOR_MULT_DOSStub_5413 {
  strings:
    $key_5413 = { 00 7b [2] 74 63 [2] 33 61 [2] 74 70 [2] 3a 7c [2] 36 76 [2] 21 7d [2] 3a 33 [2] 07 }

  condition:
    any of them
}