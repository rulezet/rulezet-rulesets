rule TTP_XOR_MULT_DOSStub_fab4 {
  strings:
    $key_fab4 = { ae dc [2] da c4 [2] 9d c6 [2] da d7 [2] 94 db [2] 98 d1 [2] 8f da [2] 94 94 [2] a9 }

  condition:
    any of them
}