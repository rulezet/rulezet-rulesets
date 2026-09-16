rule TTP_XOR_MULT_DOSStub_66a2 {
  strings:
    $key_66a2 = { 32 ca [2] 46 d2 [2] 01 d0 [2] 46 c1 [2] 08 cd [2] 04 c7 [2] 13 cc [2] 08 82 [2] 35 }

  condition:
    any of them
}