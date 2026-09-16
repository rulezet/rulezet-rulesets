rule TTP_XOR_MULT_DOSStub_12a2 {
  strings:
    $key_12a2 = { 46 ca [2] 32 d2 [2] 75 d0 [2] 32 c1 [2] 7c cd [2] 70 c7 [2] 67 cc [2] 7c 82 [2] 41 }

  condition:
    any of them
}