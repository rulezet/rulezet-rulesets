rule TTP_XOR_MULT_DOSStub_11a0 {
  strings:
    $key_11a0 = { 45 c8 [2] 31 d0 [2] 76 d2 [2] 31 c3 [2] 7f cf [2] 73 c5 [2] 64 ce [2] 7f 80 [2] 42 }

  condition:
    any of them
}