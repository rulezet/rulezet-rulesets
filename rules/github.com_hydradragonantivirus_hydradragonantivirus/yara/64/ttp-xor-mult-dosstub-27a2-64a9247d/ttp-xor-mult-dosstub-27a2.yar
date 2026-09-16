rule TTP_XOR_MULT_DOSStub_27a2 {
  strings:
    $key_27a2 = { 73 ca [2] 07 d2 [2] 40 d0 [2] 07 c1 [2] 49 cd [2] 45 c7 [2] 52 cc [2] 49 82 [2] 74 }

  condition:
    any of them
}