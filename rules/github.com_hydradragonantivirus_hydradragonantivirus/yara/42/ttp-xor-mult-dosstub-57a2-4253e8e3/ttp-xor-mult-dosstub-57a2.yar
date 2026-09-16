rule TTP_XOR_MULT_DOSStub_57a2 {
  strings:
    $key_57a2 = { 03 ca [2] 77 d2 [2] 30 d0 [2] 77 c1 [2] 39 cd [2] 35 c7 [2] 22 cc [2] 39 82 [2] 04 }

  condition:
    any of them
}