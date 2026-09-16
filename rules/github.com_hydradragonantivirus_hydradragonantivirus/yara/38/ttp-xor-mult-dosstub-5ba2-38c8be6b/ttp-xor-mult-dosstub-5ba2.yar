rule TTP_XOR_MULT_DOSStub_5ba2 {
  strings:
    $key_5ba2 = { 0f ca [2] 7b d2 [2] 3c d0 [2] 7b c1 [2] 35 cd [2] 39 c7 [2] 2e cc [2] 35 82 [2] 08 }

  condition:
    any of them
}