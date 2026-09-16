rule TTP_XOR_MULT_DOSStub_e370 {
  strings:
    $key_e370 = { b7 18 [2] c3 00 [2] 84 02 [2] c3 13 [2] 8d 1f [2] 81 15 [2] 96 1e [2] 8d 50 [2] b0 }

  condition:
    any of them
}