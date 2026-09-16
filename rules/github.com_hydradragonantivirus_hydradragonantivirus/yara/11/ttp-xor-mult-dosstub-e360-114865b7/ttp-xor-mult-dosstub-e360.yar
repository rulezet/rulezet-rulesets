rule TTP_XOR_MULT_DOSStub_e360 {
  strings:
    $key_e360 = { b7 08 [2] c3 10 [2] 84 12 [2] c3 03 [2] 8d 0f [2] 81 05 [2] 96 0e [2] 8d 40 [2] b0 }

  condition:
    any of them
}