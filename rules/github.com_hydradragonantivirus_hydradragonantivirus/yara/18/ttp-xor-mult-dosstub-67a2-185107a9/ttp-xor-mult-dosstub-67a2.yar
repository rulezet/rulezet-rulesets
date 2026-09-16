rule TTP_XOR_MULT_DOSStub_67a2 {
  strings:
    $key_67a2 = { 33 ca [2] 47 d2 [2] 00 d0 [2] 47 c1 [2] 09 cd [2] 05 c7 [2] 12 cc [2] 09 82 [2] 34 }

  condition:
    any of them
}