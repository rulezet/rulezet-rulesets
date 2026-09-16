rule TTP_XOR_MULT_DOSStub_2aa2 {
  strings:
    $key_2aa2 = { 7e ca [2] 0a d2 [2] 4d d0 [2] 0a c1 [2] 44 cd [2] 48 c7 [2] 5f cc [2] 44 82 [2] 79 }

  condition:
    any of them
}