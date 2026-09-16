rule TTP_XOR_MULT_DOSStub_eba2 {
  strings:
    $key_eba2 = { bf ca [2] cb d2 [2] 8c d0 [2] cb c1 [2] 85 cd [2] 89 c7 [2] 9e cc [2] 85 82 [2] b8 }

  condition:
    any of them
}