rule TTP_XOR_MULT_DOSStub_22a2 {
  strings:
    $key_22a2 = { 76 ca [2] 02 d2 [2] 45 d0 [2] 02 c1 [2] 4c cd [2] 40 c7 [2] 57 cc [2] 4c 82 [2] 71 }

  condition:
    any of them
}