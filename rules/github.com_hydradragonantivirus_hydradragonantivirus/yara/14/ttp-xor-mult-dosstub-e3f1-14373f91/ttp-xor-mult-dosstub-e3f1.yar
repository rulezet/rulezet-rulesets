rule TTP_XOR_MULT_DOSStub_e3f1 {
  strings:
    $key_e3f1 = { b7 99 [2] c3 81 [2] 84 83 [2] c3 92 [2] 8d 9e [2] 81 94 [2] 96 9f [2] 8d d1 [2] b0 }

  condition:
    any of them
}