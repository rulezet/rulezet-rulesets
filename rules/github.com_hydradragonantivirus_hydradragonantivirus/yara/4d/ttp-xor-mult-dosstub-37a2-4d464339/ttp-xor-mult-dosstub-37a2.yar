rule TTP_XOR_MULT_DOSStub_37a2 {
  strings:
    $key_37a2 = { 63 ca [2] 17 d2 [2] 50 d0 [2] 17 c1 [2] 59 cd [2] 55 c7 [2] 42 cc [2] 59 82 [2] 64 }

  condition:
    any of them
}