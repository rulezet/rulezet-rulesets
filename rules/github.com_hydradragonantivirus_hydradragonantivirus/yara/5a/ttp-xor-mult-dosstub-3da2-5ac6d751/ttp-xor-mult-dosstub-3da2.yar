rule TTP_XOR_MULT_DOSStub_3da2 {
  strings:
    $key_3da2 = { 69 ca [2] 1d d2 [2] 5a d0 [2] 1d c1 [2] 53 cd [2] 5f c7 [2] 48 cc [2] 53 82 [2] 6e }

  condition:
    any of them
}