rule TTP_XOR_MULT_DOSStub_e356 {
  strings:
    $key_e356 = { b7 3e [2] c3 26 [2] 84 24 [2] c3 35 [2] 8d 39 [2] 81 33 [2] 96 38 [2] 8d 76 [2] b0 }

  condition:
    any of them
}