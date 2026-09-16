rule TTP_XOR_MULT_DOSStub_72a0 {
  strings:
    $key_72a0 = { 26 c8 [2] 52 d0 [2] 15 d2 [2] 52 c3 [2] 1c cf [2] 10 c5 [2] 07 ce [2] 1c 80 [2] 21 }

  condition:
    any of them
}