rule TTP_XOR_MULT_DOSStub_34a2 {
  strings:
    $key_34a2 = { 60 ca [2] 14 d2 [2] 53 d0 [2] 14 c1 [2] 5a cd [2] 56 c7 [2] 41 cc [2] 5a 82 [2] 67 }

  condition:
    any of them
}