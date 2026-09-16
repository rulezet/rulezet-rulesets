rule TTP_XOR_MULT_DOSStub_63a2 {
  strings:
    $key_63a2 = { 37 ca [2] 43 d2 [2] 04 d0 [2] 43 c1 [2] 0d cd [2] 01 c7 [2] 16 cc [2] 0d 82 [2] 30 }

  condition:
    any of them
}