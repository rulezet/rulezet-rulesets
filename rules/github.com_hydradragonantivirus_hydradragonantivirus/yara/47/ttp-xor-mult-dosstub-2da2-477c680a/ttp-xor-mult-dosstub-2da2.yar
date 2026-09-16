rule TTP_XOR_MULT_DOSStub_2da2 {
  strings:
    $key_2da2 = { 79 ca [2] 0d d2 [2] 4a d0 [2] 0d c1 [2] 43 cd [2] 4f c7 [2] 58 cc [2] 43 82 [2] 7e }

  condition:
    any of them
}