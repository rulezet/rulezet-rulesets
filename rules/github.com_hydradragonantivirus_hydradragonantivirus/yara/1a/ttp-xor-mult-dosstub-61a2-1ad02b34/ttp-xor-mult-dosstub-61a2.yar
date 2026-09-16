rule TTP_XOR_MULT_DOSStub_61a2 {
  strings:
    $key_61a2 = { 35 ca [2] 41 d2 [2] 06 d0 [2] 41 c1 [2] 0f cd [2] 03 c7 [2] 14 cc [2] 0f 82 [2] 32 }

  condition:
    any of them
}