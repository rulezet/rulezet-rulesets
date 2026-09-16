rule TTP_XOR_MULT_DOSStub_3ba2 {
  strings:
    $key_3ba2 = { 6f ca [2] 1b d2 [2] 5c d0 [2] 1b c1 [2] 55 cd [2] 59 c7 [2] 4e cc [2] 55 82 [2] 68 }

  condition:
    any of them
}