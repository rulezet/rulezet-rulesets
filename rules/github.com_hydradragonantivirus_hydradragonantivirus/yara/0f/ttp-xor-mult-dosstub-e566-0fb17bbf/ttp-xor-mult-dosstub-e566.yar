rule TTP_XOR_MULT_DOSStub_e566 {
  strings:
    $key_e566 = { b1 0e [2] c5 16 [2] 82 14 [2] c5 05 [2] 8b 09 [2] 87 03 [2] 90 08 [2] 8b 46 [2] b6 }

  condition:
    any of them
}