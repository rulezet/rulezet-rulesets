rule TTP_XOR_MULT_DOSStub_07a2 {
  strings:
    $key_07a2 = { 53 ca [2] 27 d2 [2] 60 d0 [2] 27 c1 [2] 69 cd [2] 65 c7 [2] 72 cc [2] 69 82 [2] 54 }

  condition:
    any of them
}