rule TTP_XOR_MULT_DOSStub_23a2 {
  strings:
    $key_23a2 = { 77 ca [2] 03 d2 [2] 44 d0 [2] 03 c1 [2] 4d cd [2] 41 c7 [2] 56 cc [2] 4d 82 [2] 70 }

  condition:
    any of them
}