rule TTP_XOR_MULT_DOSStub_46a2 {
  strings:
    $key_46a2 = { 12 ca [2] 66 d2 [2] 21 d0 [2] 66 c1 [2] 28 cd [2] 24 c7 [2] 33 cc [2] 28 82 [2] 15 }

  condition:
    any of them
}