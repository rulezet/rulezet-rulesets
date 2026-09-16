rule TTP_XOR_MULT_DOSStub_e577 {
  strings:
    $key_e577 = { b1 1f [2] c5 07 [2] 82 05 [2] c5 14 [2] 8b 18 [2] 87 12 [2] 90 19 [2] 8b 57 [2] b6 }

  condition:
    any of them
}