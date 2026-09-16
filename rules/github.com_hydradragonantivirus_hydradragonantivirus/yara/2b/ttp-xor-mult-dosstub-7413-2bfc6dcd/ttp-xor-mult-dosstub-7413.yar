rule TTP_XOR_MULT_DOSStub_7413 {
  strings:
    $key_7413 = { 20 7b [2] 54 63 [2] 13 61 [2] 54 70 [2] 1a 7c [2] 16 76 [2] 01 7d [2] 1a 33 [2] 27 }

  condition:
    any of them
}