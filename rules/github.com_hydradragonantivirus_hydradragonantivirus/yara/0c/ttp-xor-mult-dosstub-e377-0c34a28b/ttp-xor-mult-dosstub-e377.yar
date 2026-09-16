rule TTP_XOR_MULT_DOSStub_e377 {
  strings:
    $key_e377 = { b7 1f [2] c3 07 [2] 84 05 [2] c3 14 [2] 8d 18 [2] 81 12 [2] 96 19 [2] 8d 57 [2] b0 }

  condition:
    any of them
}