rule TTP_XOR_MULT_DOSStub_5af6 {
  strings:
    $key_5af6 = { 0e 9e [2] 7a 86 [2] 3d 84 [2] 7a 95 [2] 34 99 [2] 38 93 [2] 2f 98 [2] 34 d6 [2] 09 }

  condition:
    any of them
}