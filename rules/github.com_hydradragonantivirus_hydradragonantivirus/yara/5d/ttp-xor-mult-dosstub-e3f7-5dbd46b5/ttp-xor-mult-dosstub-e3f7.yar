rule TTP_XOR_MULT_DOSStub_e3f7 {
  strings:
    $key_e3f7 = { b7 9f [2] c3 87 [2] 84 85 [2] c3 94 [2] 8d 98 [2] 81 92 [2] 96 99 [2] 8d d7 [2] b0 }

  condition:
    any of them
}