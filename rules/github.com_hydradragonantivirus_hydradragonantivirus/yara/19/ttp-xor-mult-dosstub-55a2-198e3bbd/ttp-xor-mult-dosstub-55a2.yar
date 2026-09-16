rule TTP_XOR_MULT_DOSStub_55a2 {
  strings:
    $key_55a2 = { 01 ca [2] 75 d2 [2] 32 d0 [2] 75 c1 [2] 3b cd [2] 37 c7 [2] 20 cc [2] 3b 82 [2] 06 }

  condition:
    any of them
}