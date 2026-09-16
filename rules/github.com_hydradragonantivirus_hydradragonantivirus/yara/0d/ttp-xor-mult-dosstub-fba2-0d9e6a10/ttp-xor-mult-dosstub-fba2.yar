rule TTP_XOR_MULT_DOSStub_fba2 {
  strings:
    $key_fba2 = { af ca [2] db d2 [2] 9c d0 [2] db c1 [2] 95 cd [2] 99 c7 [2] 8e cc [2] 95 82 [2] a8 }

  condition:
    any of them
}