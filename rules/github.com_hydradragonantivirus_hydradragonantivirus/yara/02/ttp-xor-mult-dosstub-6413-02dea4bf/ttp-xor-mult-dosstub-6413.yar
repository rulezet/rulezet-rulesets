rule TTP_XOR_MULT_DOSStub_6413 {
  strings:
    $key_6413 = { 30 7b [2] 44 63 [2] 03 61 [2] 44 70 [2] 0a 7c [2] 06 76 [2] 11 7d [2] 0a 33 [2] 37 }

  condition:
    any of them
}