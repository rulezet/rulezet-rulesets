rule TTP_XOR_MULT_DOSStub_03a2 {
  strings:
    $key_03a2 = { 57 ca [2] 23 d2 [2] 64 d0 [2] 23 c1 [2] 6d cd [2] 61 c7 [2] 76 cc [2] 6d 82 [2] 50 }

  condition:
    any of them
}