rule TTP_XOR_MULT_DOSStub_0da2 {
  strings:
    $key_0da2 = { 59 ca [2] 2d d2 [2] 6a d0 [2] 2d c1 [2] 63 cd [2] 6f c7 [2] 78 cc [2] 63 82 [2] 5e }

  condition:
    any of them
}