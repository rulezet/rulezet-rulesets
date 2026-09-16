rule TTP_XOR_MULT_DOSStub_1513 {
  strings:
    $key_1513 = { 41 7b [2] 35 63 [2] 72 61 [2] 35 70 [2] 7b 7c [2] 77 76 [2] 60 7d [2] 7b 33 [2] 46 }

  condition:
    any of them
}