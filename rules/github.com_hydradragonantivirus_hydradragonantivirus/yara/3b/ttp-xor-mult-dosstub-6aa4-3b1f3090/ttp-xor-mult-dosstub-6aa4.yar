rule TTP_XOR_MULT_DOSStub_6aa4 {
  strings:
    $key_6aa4 = { 3e cc [2] 4a d4 [2] 0d d6 [2] 4a c7 [2] 04 cb [2] 08 c1 [2] 1f ca [2] 04 84 [2] 39 }

  condition:
    any of them
}