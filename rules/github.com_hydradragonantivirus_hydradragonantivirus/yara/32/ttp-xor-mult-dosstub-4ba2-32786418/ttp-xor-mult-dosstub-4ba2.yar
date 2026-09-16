rule TTP_XOR_MULT_DOSStub_4ba2 {
  strings:
    $key_4ba2 = { 1f ca [2] 6b d2 [2] 2c d0 [2] 6b c1 [2] 25 cd [2] 29 c7 [2] 3e cc [2] 25 82 [2] 18 }

  condition:
    any of them
}