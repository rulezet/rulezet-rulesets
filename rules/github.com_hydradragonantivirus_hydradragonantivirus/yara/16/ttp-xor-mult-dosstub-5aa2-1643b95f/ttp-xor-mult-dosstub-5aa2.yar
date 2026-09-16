rule TTP_XOR_MULT_DOSStub_5aa2 {
  strings:
    $key_5aa2 = { 0e ca [2] 7a d2 [2] 3d d0 [2] 7a c1 [2] 34 cd [2] 38 c7 [2] 2f cc [2] 34 82 [2] 09 }

  condition:
    any of them
}