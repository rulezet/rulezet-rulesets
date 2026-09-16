rule TTP_XOR_MULT_DOSStub_65a2 {
  strings:
    $key_65a2 = { 31 ca [2] 45 d2 [2] 02 d0 [2] 45 c1 [2] 0b cd [2] 07 c7 [2] 10 cc [2] 0b 82 [2] 36 }

  condition:
    any of them
}