rule TTP_XOR_MULT_DOSStub_05a2 {
  strings:
    $key_05a2 = { 51 ca [2] 25 d2 [2] 62 d0 [2] 25 c1 [2] 6b cd [2] 67 c7 [2] 70 cc [2] 6b 82 [2] 56 }

  condition:
    any of them
}