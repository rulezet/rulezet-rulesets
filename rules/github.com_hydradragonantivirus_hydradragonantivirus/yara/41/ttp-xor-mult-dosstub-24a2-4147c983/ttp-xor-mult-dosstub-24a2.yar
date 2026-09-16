rule TTP_XOR_MULT_DOSStub_24a2 {
  strings:
    $key_24a2 = { 70 ca [2] 04 d2 [2] 43 d0 [2] 04 c1 [2] 4a cd [2] 46 c7 [2] 51 cc [2] 4a 82 [2] 77 }

  condition:
    any of them
}