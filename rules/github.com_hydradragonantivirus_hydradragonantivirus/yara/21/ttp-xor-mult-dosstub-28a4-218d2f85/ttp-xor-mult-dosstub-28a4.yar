rule TTP_XOR_MULT_DOSStub_28a4 {
  strings:
    $key_28a4 = { 7c cc [2] 08 d4 [2] 4f d6 [2] 08 c7 [2] 46 cb [2] 4a c1 [2] 5d ca [2] 46 84 [2] 7b }

  condition:
    any of them
}