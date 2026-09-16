rule TTP_XOR_MULT_DOSStub_faa0 {
  strings:
    $key_faa0 = { ae c8 [2] da d0 [2] 9d d2 [2] da c3 [2] 94 cf [2] 98 c5 [2] 8f ce [2] 94 80 [2] a9 }

  condition:
    any of them
}