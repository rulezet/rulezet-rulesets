rule TTP_XOR_MULT_DOSStub_32a0 {
  strings:
    $key_32a0 = { 66 c8 [2] 12 d0 [2] 55 d2 [2] 12 c3 [2] 5c cf [2] 50 c5 [2] 47 ce [2] 5c 80 [2] 61 }

  condition:
    any of them
}