rule TTP_XOR_MULT_DOSStub_7da2 {
  strings:
    $key_7da2 = { 29 ca [2] 5d d2 [2] 1a d0 [2] 5d c1 [2] 13 cd [2] 1f c7 [2] 08 cc [2] 13 82 [2] 2e }

  condition:
    any of them
}