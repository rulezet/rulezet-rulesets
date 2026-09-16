rule TTP_XOR_MULT_DOSStub_e666 {
  strings:
    $key_e666 = { b2 0e [2] c6 16 [2] 81 14 [2] c6 05 [2] 88 09 [2] 84 03 [2] 93 08 [2] 88 46 [2] b5 }

  condition:
    any of them
}