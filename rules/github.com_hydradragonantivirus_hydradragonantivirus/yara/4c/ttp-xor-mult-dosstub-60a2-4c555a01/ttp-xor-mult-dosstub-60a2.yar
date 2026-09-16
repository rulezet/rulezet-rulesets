rule TTP_XOR_MULT_DOSStub_60a2 {
  strings:
    $key_60a2 = { 34 ca [2] 40 d2 [2] 07 d0 [2] 40 c1 [2] 0e cd [2] 02 c7 [2] 15 cc [2] 0e 82 [2] 33 }

  condition:
    any of them
}