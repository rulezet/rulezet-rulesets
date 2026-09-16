rule TTP_XOR_MULT_DOSStub_57a3 {
  strings:
    $key_57a3 = { 03 cb [2] 77 d3 [2] 30 d1 [2] 77 c0 [2] 39 cc [2] 35 c6 [2] 22 cd [2] 39 83 [2] 04 }

  condition:
    any of them
}