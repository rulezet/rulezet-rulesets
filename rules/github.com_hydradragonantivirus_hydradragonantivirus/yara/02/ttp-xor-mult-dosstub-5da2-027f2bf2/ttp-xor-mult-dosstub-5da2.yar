rule TTP_XOR_MULT_DOSStub_5da2 {
  strings:
    $key_5da2 = { 09 ca [2] 7d d2 [2] 3a d0 [2] 7d c1 [2] 33 cd [2] 3f c7 [2] 28 cc [2] 33 82 [2] 0e }

  condition:
    any of them
}