rule TTP_XOR_MULT_DOSStub_e346 {
  strings:
    $key_e346 = { b7 2e [2] c3 36 [2] 84 34 [2] c3 25 [2] 8d 29 [2] 81 23 [2] 96 28 [2] 8d 66 [2] b0 }

  condition:
    any of them
}