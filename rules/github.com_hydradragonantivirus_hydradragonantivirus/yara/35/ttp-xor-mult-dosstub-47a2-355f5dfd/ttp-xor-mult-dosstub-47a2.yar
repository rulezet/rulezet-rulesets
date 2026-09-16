rule TTP_XOR_MULT_DOSStub_47a2 {
  strings:
    $key_47a2 = { 13 ca [2] 67 d2 [2] 20 d0 [2] 67 c1 [2] 29 cd [2] 25 c7 [2] 32 cc [2] 29 82 [2] 14 }

  condition:
    any of them
}